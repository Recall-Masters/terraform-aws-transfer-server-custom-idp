import os
import json
import boto3
import base64
from botocore.exceptions import ClientError


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
    resp_data = {}
    bucket_name = os.getenv('BUCKET_NAME')

    if 'username' not in event or 'serverId' not in event:
        print("Incoming username or serverId missing  - Unexpected")
        return {}

    # It is recommended to verify server ID against some value, this template
    # does not verify server ID
    input_username = event['username']
    print(
        "Username: {}, ServerId: {}".format(input_username, event['serverId']));

    if 'password' in event:
        input_password = event['password']
    else:
        print("No password, checking for SSH public key")
        input_password = ''

    # Lookup user's secret which can contain the password or SSH public keys
    resp = get_secret("SFTP/" + input_username)

    if resp is not None:
        resp_dict = json.loads(resp)
    else:
        print("Secrets Manager exception thrown")
        return {}

    if input_password != '':
        if 'Password' in resp_dict:
            resp_password = resp_dict['Password']
        else:
            print(
                "Unable to authenticate user - No field match in Secret for password")
            return {}

        if resp_password != input_password:
            print(
                "Unable to authenticate user - Incoming password does not match stored")
            return {}
    else:
        # SSH Public Key Auth Flow - The incoming password was empty so we are trying ssh auth and need to return the public key data if we have it
        if 'PublicKey' in resp_dict:
            resp_data['PublicKeys'] = [resp_dict['PublicKey']]
        else:
            print("Unable to authenticate user - No public keys found")
            return {}

    # If we've got this far then we've either authenticated the user by password or we're using SSH public key auth and
    # we've begun constructing the data response. Check for each key value pair.
    # These are required so set to empty string if missing
    resp_data['Role'] = resp_dict.get('Role')

    # These are optional so ignore if not present
    if 'Policy' in resp_dict:
        resp_data['Policy'] = resp_dict['Policy']

    home_directory = resp_dict['HomeDirectory']
    if not resp_data['Role']:
        resp_data['Role'] = os.getenv('DEFAULT_IAM_ROLE_ARN')
        resp_data['Policy'] = json.dumps(construct_policy(
            bucket_name=bucket_name,
            home_directory=home_directory,
        ))

    if 'HomeDirectoryDetails' in resp_dict:
        print(
            "HomeDirectoryDetails found - Applying setting for virtual folders",
        )
        resp_data['HomeDirectoryDetails'] = resp_dict['HomeDirectoryDetails']

    elif 'HomeDirectory' in resp_dict:
        print("HomeDirectory found - Cannot be used with HomeDirectoryDetails")
        resp_data['HomeDirectory'] = f'/{bucket_name}/{home_directory}'

    else:
        print("HomeDirectory not found - Defaulting to /")

    resp_data['HomeDirectoryType'] = "LOGICAL"

    print("Completed Response Data: " + json.dumps(resp_data))
    return resp_data


def get_secret(id):
    region = os.environ['SecretsManagerRegion']
    print("Secrets Manager Region: " + region)

    client = boto3.session.Session().client(service_name='secretsmanager',
                                            region_name=region)

    try:
        resp = client.get_secret_value(SecretId=id)
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in resp:
            print("Found Secret String")
            return resp['SecretString']
        else:
            print("Found Binary Secret")
            return base64.b64decode(resp['SecretBinary'])
    except ClientError as err:
        print('Error Talking to SecretsManager: ' + err.response['Error'][
            'Code'] + ', Message: ' + str(err))
        return None
