import logging
import os
import json
import boto3
import base64
from botocore.exceptions import ClientError

import sentry_sdk
from jinja2 import Template, StrictUndefined
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

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


ALLOWED_TYPES = frozenset({
    'vin_check',
    'inventory_check',
    'dms',
    'prospect',
})


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


def generate_home_directory(
    template: str,
    secret: dict,
    user_name: str,
) -> str:
    """
    Generate the home path for the user.

    This function is currently hard code. Later, it should be replaced with a
    dynamic Jinja2 template supplied as a Terraform module parameter (and then
    as a Lambda function environment variable).

    :param template: Jinja2 template to render the path;
    :param user_name: Name of the SFTP user;
    :param secret: User parameters from AWS Secrets Manager.
    :return: Full absolute path in the format AWS Transfer can understand.
    """
    return Template(
        template,
        undefined=StrictUndefined,
        lstrip_blocks=True,
        trim_blocks=True,
        keep_trailing_newline=False,
    ).render(
        secret=secret,
        user_name=user_name,
    ).strip()


def generate_absolute_path(home_directory: str, bucket_name: str) -> str:
    """
    Generate absolute S3 path in the format that SFTP Transfer accepts.

    :param bucket_name: bucket;
    :param home_directory: directory in the bucket.
    :return: path.
    """
    return f'/{bucket_name}/{home_directory}'


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
    resp = get_secret("SFTP/" + input_username)

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
        # SSH Public Key Auth Flow - The incoming password was empty so we are trying ssh auth and need to return the public key data if we have it
        if 'PublicKey' in resp_dict:
            resp_data['PublicKeys'] = [resp_dict['PublicKey']]
        else:
            logger.error('Unable to authenticate user - No public keys found')
            return {}

    # If we've got this far then we've either authenticated the user by password or we're using SSH public key auth and
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

    logger.error("Completed Response Data: " + json.dumps(resp_data))
    return resp_data


def get_secret(id):
    region = os.environ['SecretsManagerRegion']
    logger.info("Secrets Manager Region: " + region)

    client = boto3.session.Session().client(service_name='secretsmanager',
                                            region_name=region)

    try:
        resp = client.get_secret_value(SecretId=id)
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in resp:
            logger.info("Found Secret String")
            return resp['SecretString']
        else:
            logger.info("Found Binary Secret")
            return base64.b64decode(resp['SecretBinary'])
    except ClientError as err:
        logger.error('Error Talking to SecretsManager: ' + err.response['Error'][
            'Code'] + ', Message: ' + str(err))
        return None
