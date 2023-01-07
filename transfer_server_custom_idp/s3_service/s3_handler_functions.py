import logging

import boto3

from transfer_server_custom_idp.settings import (
    HOME_DIRECTORY_TO_FOLDERS_MAPPING,
    SFTP_COMPANY_PREFIX,
)

logger = logging.getLogger(__name__)


def s3_path_existence_check(
    bucket_name: str,
    path: str,
) -> bool:
    """Checks the existence of path in AWS S3 bucket."""
    try:
        logger.info("Path to check: %s", path)
        s3_client = boto3.client("s3")
        path_content = s3_client.list_objects(
            Bucket=bucket_name,
            Prefix=path,
            MaxKeys=1,
        )["Content"]
    except Exception as error:
        logger.exception("Exception occurred: %s", error)
        raise Exception
    if len(path_content) > 0:
        return True
    return False


def create_folder_in_s3(
    bucket_name: str,
    folder_path: str,
) -> None:
    """Creates path in AWS S3 bucket without object upload."""
    try:
        logger.info("Folder path to create: %s", folder_path)
        s3_client = boto3.client("s3")
        s3_client.put_object(
            Bucket=bucket_name,
            Body="",
            Key=folder_path,
        )
    except Exception as error:
        logger.exception("Exception occurred: %s", error)
        raise Exception


def onboard_new_user_with_home_directory_folders_in_s3(
    home_directory: str,
    bucket_name: str,
) -> None:
    """Creates the home directory folders based on home directory prefix."""
    for mapping_key in HOME_DIRECTORY_TO_FOLDERS_MAPPING.keys():
        if mapping_key in home_directory and mapping_key != SFTP_COMPANY_PREFIX:
            for folder in HOME_DIRECTORY_TO_FOLDERS_MAPPING[mapping_key]:
                create_folder_in_s3(
                    bucket_name=bucket_name,
                    folder_path=f"{home_directory}/{folder}/",
                )
        if SFTP_COMPANY_PREFIX in home_directory:
            for folder in HOME_DIRECTORY_TO_FOLDERS_MAPPING[SFTP_COMPANY_PREFIX]:
                create_folder_in_s3(
                    bucket_name=bucket_name,
                    folder_path=f"{home_directory.rsplit('/', 1)[0]}/{folder}/",
                )
