import logging
import os
import json
import boto3
import base64

import sentry_sdk
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

from transfer_server_custom_idp.errors import UserNotFound
from transfer_server_custom_idp.home_directory import (
    generate_home_directory,
    generate_absolute_path,
)

logger = logging.getLogger(__name__)

SENTRY_DSN = os.getenv('SENTRY_DSN')
ENV = os.getenv('ENV')

if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[AwsLambdaIntegration()],
        environment=ENV,
        sample_rate=1.0,
    )


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


def lambda_handler(event, _context):
    """
    Lambda entry point.

    Construct the response and return it. Catch errors and make sure they reach
    Sentry.
    """
    home_directory_template = os.getenv('HOME_DIRECTORY_TEMPLATE')

    try:
        return construct_response(
            event=event,
            home_directory_template=home_directory_template,
        )
    except Exception as err:
        sentry_sdk.capture_exception(err)

    return {}


def construct_response(
    event: dict,
    home_directory_template: str,
):
    resp_data = {}
    bucket_name = os.getenv('BUCKET_NAME')

    if 'username' not in event or 'serverId' not in event:
        logger.error("Incoming username or serverId missing  - Unexpected")
        return {}

    # It is recommended to verify server ID against some value, this template
    # does not verify server ID
    input_username = event['username']
    logger.info(
        'User name: %s, server ID: %s',
        input_username,
        event['serverId'],
    )

    if 'password' in event:
        input_password = event['password']
    else:
        logger.info("No password, checking for SSH public key")
        input_password = ''

    # Lookup user's secret which can contain the password or SSH public keys
    resp = get_secret(
        username=input_username,
        secrets_manager_prefix='SFTP',
        aws_region=os.environ['SECRETS_MANAGER_REGION'],
    )

    if resp is not None:
        resp_dict = json.loads(resp)
    else:
        logger.error("Secrets Manager exception thrown")
        return {}

    if input_password != '':
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
