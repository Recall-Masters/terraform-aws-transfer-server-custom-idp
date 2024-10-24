import json
import os
import re

import boto3
from passlib.hash import pbkdf2_sha256
from structlog.stdlib import BoundLogger

from transfer_server_custom_idp.errors import (IncorrectPassword,
                                               IncorrectUserConfiguration,
                                               MissingCredentials)
from transfer_server_custom_idp.home_directory import (generate_absolute_path,
                                                       generate_home_directory)
from transfer_server_custom_idp.models.secret_model import (
    AWSTransferResponse, Login, Secret)
from transfer_server_custom_idp.s3_service import s3_handler_functions
from transfer_server_custom_idp.secrets_manager_service import \
    secrets_manager_handler
from transfer_server_custom_idp.settings import (
    INCOMING_FOLDERS, SFTP_COMPANY_PREFIX_REGEX,
    SFTP_COMPANY_TYPE_SUFFIX_REGEX, USERNAME_HOME_DIRECTORY_PATTERN)


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
        "Version": "2012-10-17",
        "Statement": [
            {
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [
                            f"{home_directory}/*",
                            f"{home_directory}/",
                            f"{home_directory}",
                        ],
                    },
                },
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Action": "s3:ListBucket",
                "Effect": "Allow",
                "Sid": "ListHomeDir",
            },
            {
                "Sid": "AWSTransferRequirements",
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketLocation",
                ],
                "Resource": "*",
            },
            {
                "Resource": "arn:aws:s3:::*",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObjectVersion",
                    "s3:DeleteObject",
                    "s3:GetObjectVersion",
                    "s3:GetObjectACL",
                    "s3:PutObjectACL",
                ],
                "Effect": "Allow",
                "Sid": "HomeDirObjectAccess",
            },
        ],
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
    session = boto3.session.Session()
    # Lookup user's secret which can contain the password or SSH public keys
    secret_configuration_string = secrets_manager_handler.get_secret(
        username=input_username,
        secrets_manager_prefix="SFTP",
        aws_region=os.environ["SECRETS_MANAGER_REGION"],
        session=session,
        logger=logger,
    )

    if secret_configuration_string is not None:
        secret_config_dictionary = json.loads(secret_configuration_string)
        secret_configuration = Secret(
            user_name=input_username,
            home_directory_details="HomeDirectoryDetails" in secret_config_dictionary,
        ).update(
            secret_config_dictionary,
        )
    else:
        logger.error("Secrets Manager exception thrown")
        return {}
    ssh_key = secret_configuration.key
    user_password = secret_configuration.password
    user_ftp_password = secret_configuration.ftp_password
    ftp_ssh_key = secret_configuration.ftp_ssh
    is_decrypted_password_valid = False
    is_decrypted_ftp_password_valid = False
    ftp_user = False

    if input_password:
        if user_password != input_password and user_ftp_password != input_password:
            logger.info(
                'Password one to one check was failed for user %s.'
                ' Trying to check against pbkdf2 hash.',
                input_username,
            )
            user_hash_value = secret_configuration.hash_value
            user_ftp_hash_value = secret_configuration.ftp_hash_value
            if user_hash_value:
                is_decrypted_password_valid = pbkdf2_sha256.verify(
                    input_password,
                    user_hash_value,
                )
            elif user_ftp_hash_value:
                is_decrypted_ftp_password_valid = pbkdf2_sha256.verify(
                    input_password,
                    user_ftp_hash_value,
                )
            if not is_decrypted_password_valid and not is_decrypted_ftp_password_valid:
                raise IncorrectPassword()
            if is_decrypted_ftp_password_valid and not is_decrypted_password_valid:
                ftp_user = True
        if user_ftp_password == input_password and user_password != input_password:
            ftp_user = True

    response_object = AWSTransferResponse()
    if ssh_key:
        logger.info(
            'SSH key was found to authorize for user %s.',
            input_username,
        )
        response_object.public_keys = [ssh_key]
    elif ftp_ssh_key:
        logger.info(
            'FTP SSH key was found to authorize for user %s.',
            input_username,
        )
        response_object.public_keys = [ftp_ssh_key]
        ftp_user = True
    elif not input_password:
        raise MissingCredentials()

    if ftp_user:
        if secret_configuration.ftp_dealer_id:
            secret_configuration.dealer_id = secret_configuration.ftp_dealer_id
        if secret_configuration.ftp_company_id:
            secret_configuration.company_id = secret_configuration.ftp_company_id
        if secret_configuration.ftp_type:
            secret_configuration.type = secret_configuration.ftp_type

    if (
        not secret_configuration.company_id and
        secret_configuration.type != 'static'
    ):
        if dealer_id := secret_configuration.dealer_id:
            secret_configuration.company_id = dealer_id
        else:
            logger.error(
                "Company id or dealer id "
                "are not presented in SFTP user "
                "configuration.",
            )
            raise IncorrectUserConfiguration()


    # If we've got this far then we've either authenticated the user by password
    # or we're using SSH public key auth and
    # we've begun constructing the data response. Check for each key value pair.
    # These are required so set to empty string if missing
    response["Role"] = secret_configuration.role

    # These are optional so ignore if not present
    if secret_configuration.policy:
        response["Policy"] = secret_configuration.policy

    home_directory = generate_home_directory(
        template=home_directory_template,
        secret=secret_configuration,
    )
    if secret_configuration.shared:
        home_directory = re.sub(
            USERNAME_HOME_DIRECTORY_PATTERN,
            '',
            home_directory,
        )
        logger.info(
            'Shared home directory: %s will be created for user: %s',
            home_directory,
            input_username,
        )
    s3_client = session.client(
        service_name="s3",
        region_name=os.environ["SECRETS_MANAGER_REGION"],
    )
    if not s3_handler_functions.s3_path_existence_check(
            bucket_name=bucket_name,
            path=home_directory,
            s3_client=s3_client,
    ):
        s3_handler_functions.onboard_new_user_with_home_directory_folders_in_s3(
            bucket_name=bucket_name,
            home_directory=home_directory,
            s3_client=s3_client,
        )
    if re.match(rf"{SFTP_COMPANY_PREFIX_REGEX}", home_directory) and re.match(
            rf"{SFTP_COMPANY_TYPE_SUFFIX_REGEX}",
            home_directory,
    ):
        for folder in INCOMING_FOLDERS:
            if not s3_handler_functions.s3_path_existence_check(
                    bucket_name=bucket_name,
                    path=f'{home_directory}/{folder}/',
                    s3_client=s3_client,
            ):
                s3_handler_functions.onboard_new_user_with_home_directory_folders_in_s3(
                    bucket_name=bucket_name,
                    home_directory=f'{home_directory}/{folder}',
                    s3_client=s3_client,
                    recreate_company_folder=True,
                )

    if not response["Role"]:
        response["Role"] = os.getenv("DEFAULT_IAM_ROLE_ARN")
        response["Policy"] = json.dumps(
            construct_policy(
                bucket_name=bucket_name,
                home_directory=home_directory,
            ),
        )

    if secret_configuration.home_directory_details:
        raise ValueError("`HomeDirectoryDetails` is not supported.")

    response["HomeDirectoryType"] = "LOGICAL"
    response["HomeDirectoryDetails"] = json.dumps(
        [
            {
                "Entry": "/",
                "Target": generate_absolute_path(
                    home_directory=home_directory,
                    bucket_name=bucket_name,
                ),
            },
        ],
    )

    if response.get("HomeDirectory") is not None:
        del response["HomeDirectory"]

    response.update(response_object.dict(by_alias=True))

    logger.info(
        "User has been successfully authenticated",
        response=response,
    )

    return response
