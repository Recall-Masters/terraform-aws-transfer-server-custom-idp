import base64
import json
import os

import boto3
from structlog import BoundLogger

from transfer_server_custom_idp.errors import (
    UserNotFound, IncorrectPassword,
    MissingCredentials,
)
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
    response = {}

    # It is recommended to verify server ID against some value, this template
    # does not verify server ID
    input_username = login.username
    input_password = login.password

    # Lookup user's secret which can contain the password or SSH public keys
    secret_configuration_string = get_secret(
        username=input_username,
        secrets_manager_prefix='SFTP',
        aws_region=os.environ['SECRETS_MANAGER_REGION'],
        logger=logger,
    )

    if secret_configuration_string is not None:
        secret_configuration = json.loads(secret_configuration_string)
    else:
        logger.error("Secrets Manager exception thrown")
        return {}

    if input_password:
        if 'password' in secret_configuration:
            resp_password = secret_configuration['password']
        else:
            raise MissingCredentials()

        if resp_password != input_password:
            raise IncorrectPassword()
    else:
        # SSH Public Key Auth Flow - The incoming password was empty
        # so we are trying ssh auth and need to return the public key data
        # if we have it
        if 'PublicKey' in secret_configuration:
            response['PublicKeys'] = [secret_configuration['PublicKey']]
        else:
            return {}

    # If we've got this far then we've either authenticated the user by password
    # or we're using SSH public key auth and
    # we've begun constructing the data response. Check for each key value pair.
    # These are required so set to empty string if missing
    response['Role'] = secret_configuration.get('Role')

    # These are optional so ignore if not present
    if 'Policy' in secret_configuration:
        response['Policy'] = secret_configuration['Policy']

    home_directory = generate_home_directory(
        template=home_directory_template,
        secret=secret_configuration,
        user_name=input_username,
    )

    if not response['Role']:
        response['Role'] = os.getenv('DEFAULT_IAM_ROLE_ARN')
        response['Policy'] = json.dumps(construct_policy(
            bucket_name=bucket_name,
            home_directory=home_directory,
        ))

    if 'HomeDirectoryDetails' in secret_configuration:
        raise ValueError('`HomeDirectoryDetails` is not supported.')

    response['HomeDirectoryType'] = 'LOGICAL'
    response['HomeDirectoryDetails'] = json.dumps([{
        'Entry': '/',
        'Target': generate_absolute_path(
            home_directory=home_directory,
            bucket_name=bucket_name,
        ),
    }])

    if response.get('HomeDirectory') is not None:
        del response['HomeDirectory']

    logger.info(
        'User has been successfully authenticated',
        response=response,
    )

    return response


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
