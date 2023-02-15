import json
import os

import boto3
from structlog import BoundLogger

from transfer_server_custom_idp.errors import (
    IncorrectUserConfiguration,
    IncorrectPassword,
    MissingCredentials,
)
from transfer_server_custom_idp.home_directory import (
    generate_home_directory,
    generate_absolute_path,
)
from transfer_server_custom_idp.models.secret_model import (
    AWSTransferResponse,
    Login,
    Secret,
)
from transfer_server_custom_idp.s3_service import s3_handler_functions
from transfer_server_custom_idp.secrets_manager_service import secrets_manager_handler


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
    user_password = secret_configuration.password
    if user_password and (user_password != input_password):
        raise IncorrectPassword()

    if not secret_configuration.company_id:
        if dealer_id := secret_configuration.dealer_id:
            secret_configuration.company_id = dealer_id
        else:
            logger.error(
                "Company id or dealer id "
                "are not presented in SFTP user "
                "configuration."
            )
            raise IncorrectUserConfiguration()

    response_object = AWSTransferResponse()
    if key := secret_configuration.key:
        response_object.public_keys = [key]

    elif not user_password:
        raise MissingCredentials()

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
    if not response["Role"]:
        response["Role"] = os.getenv("DEFAULT_IAM_ROLE_ARN")
        response["Policy"] = json.dumps(
            construct_policy(
                bucket_name=bucket_name,
                home_directory=home_directory,
            )
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
            }
        ]
    )

    if response.get("HomeDirectory") is not None:
        del response["HomeDirectory"]

    response.update(response_object.dict(by_alias=True))

    logger.info(
        "User has been successfully authenticated",
        response=response,
    )

    return response
