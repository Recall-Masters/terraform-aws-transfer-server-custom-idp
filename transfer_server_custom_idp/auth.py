import base64
import json
import os

import boto3
from structlog import BoundLogger

from transfer_server_custom_idp.errors import UserNotFound
from transfer_server_custom_idp.home_directory import (
    generate_home_directory,
    generate_absolute_path,
)
from transfer_server_custom_idp.models import Login


def construct_policy(
    bucket_name: str,
    home_directory: str,
):
    """
    Create the user-specific IAM policy.

    Docs: https://docs.aws.amazon.com/transfer/latest/userguide/
    custom-identity-provider-users.html#authentication-api-method
    """
    return {
        'Version': '2012-10-17',
        'Statement': [{
            'Condition': {
                'StringLike': {
                    's3:prefix': [
                        f'{home_directory}/*',
                        f'{home_directory}/',
                    ],
                },
            },
            'Resource': f'arn:aws:s3:::{bucket_name}',
            'Action': 's3:ListBucket',
            'Effect': 'Allow',
            'Sid': 'ListHomeDir',
        }, {
            'Resource': 'arn:aws:s3:::*',
            'Action': [
                's3:PutObject',
                's3:GetObject',
                's3:DeleteObjectVersion',
                's3:DeleteObject',
                's3:GetObjectVersion',
                's3:GetObjectACL',
                's3:PutObjectACL',
            ],
            'Effect': 'Allow',
            'Sid': 'HomeDirObjectAccess',
        }],
    }


def construct_response(
    login: Login,
    home_directory_template: str,
    logger: BoundLogger,
    bucket_name: str,
):
    resp_data = {}

    # It is recommended to verify server ID against some value, this template
    # does not verify server ID
    input_username = login.username
    input_password = login.password

    # Lookup user's secret which can contain the password or SSH public keys
    resp = get_secret(
        username=input_username,
        secrets_manager_prefix='SFTP',
        aws_region=os.environ['SECRETS_MANAGER_REGION'],
        logger=logger,
    )

    if resp is not None:
        resp_dict = json.loads(resp)
    else:
        logger.error("Secrets Manager exception thrown")
        return {}

    if input_password:
        if 'password' in resp_dict:
            resp_password = resp_dict['password']
        else:
            logger.error(
                'Unable to authenticate user - No field match in Secret for '
                'password',
            )
            return {}

        if resp_password != input_password:
            logger.error(
                'Unable to authenticate user - Incoming password does not '
                'match stored')
            return {}
    else:
        # SSH Public Key Auth Flow - The incoming password was empty
        # so we are trying ssh auth and need to return the public key data
        # if we have it
        if 'PublicKey' in resp_dict:
            resp_data['PublicKeys'] = [resp_dict['PublicKey']]
        else:
            return {}

    # If we've got this far then we've either authenticated the user by password
    # or we're using SSH public key auth and
    # we've begun constructing the data response. Check for each key value pair.
    # These are required so set to empty string if missing
    resp_data['Role'] = resp_dict.get('Role')

    # These are optional so ignore if not present
    if 'Policy' in resp_dict:
        resp_data['Policy'] = resp_dict['Policy']

    home_directory = generate_home_directory(
        template=home_directory_template,
        secret=resp_dict,
        user_name=input_username,
    )

    if not resp_data['Role']:
        resp_data['Role'] = os.getenv('DEFAULT_IAM_ROLE_ARN')
        resp_data['Policy'] = json.dumps(construct_policy(
            bucket_name=bucket_name,
            home_directory=home_directory,
        ))

    if 'HomeDirectoryDetails' in resp_dict:
        logger.error(
            "HomeDirectoryDetails found - Applying setting for virtual folders",
        )
        resp_data['HomeDirectoryDetails'] = resp_dict['HomeDirectoryDetails']

    resp_data['HomeDirectoryType'] = 'LOGICAL'
    resp_data['HomeDirectoryDetails'] = json.dumps([{
        'Entry': '/',
        'Target': generate_absolute_path(
            home_directory=home_directory,
            bucket_name=bucket_name,
        ),
    }])

    if resp_data.get('HomeDirectory') is not None:
        del resp_data['HomeDirectory']

    return resp_data


def get_secret(
    username: str,
    secrets_manager_prefix: str,
    aws_region: str,
    logger: BoundLogger,
):
    """Retrieve user information from AWS Secrets Manager."""
    secret_id = f'{secrets_manager_prefix}/{username}'
    client = boto3.session.Session().client(
        service_name='secretsmanager',
        region_name=aws_region,
    )

    try:
        resp = client.get_secret_value(SecretId=secret_id)
    except client.exceptions.ResourceNotFoundException as err:
        raise UserNotFound(username=username) from err

    # Depending on whether the secret is a string or binary,
    # one of these fields will be populated.
    if 'SecretString' in resp:
        logger.info("Found Secret String")
        return resp['SecretString']
    else:
        logger.info("Found Binary Secret")
        return base64.b64decode(resp['SecretBinary'])
