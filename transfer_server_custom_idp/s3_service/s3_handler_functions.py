import logging
import re

from botocore.client import BaseClient

from transfer_server_custom_idp.settings import (
    COMPANY_FOLDERS, HOME_DIRECTORY_TO_FOLDERS_MAPPING, INCOMING_FOLDERS,
    SFTP_COMPANY_PREFIX_REGEX, SFTP_COMPANY_TYPE_SUFFIX_REGEX)

logger = logging.getLogger(__name__)


def s3_path_existence_check(
    bucket_name: str,
    path: str,
    s3_client: BaseClient,
) -> bool:
    """Checks the existence of path in AWS S3 bucket."""
    if s3_client.list_objects(
        Bucket=bucket_name,
        Prefix=path,
        MaxKeys=1,
    ).get("Contents"):
        logger.info('Path : "%s" exists.', path)
        return True
    logger.info("On-boarding of new user with home directory: %s", path)
    return False


def create_folder_in_s3(
    bucket_name: str,
    folder_path: str,
    s3_client: BaseClient,
    with_default_file_name: str = "",
) -> None:
    """Creates path in AWS S3 bucket without object upload."""
    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Body="" if not with_default_file_name else b"",
            Key=(
                folder_path if not with_default_file_name
                else f'{folder_path}/{with_default_file_name}'
            ),
        )
    except Exception as error:
        logger.info("Exception occurred: %s", error)
        raise Exception


def onboard_new_user_with_home_directory_folders_in_s3(
    home_directory: str,
    bucket_name: str,
    s3_client: BaseClient,
    recreate_company_folder: bool = False,
) -> None:
    """Creates the home directory folders based on home directory prefix."""
    if recreate_company_folder:
        create_folder_in_s3(
            bucket_name=bucket_name,
            folder_path=home_directory,
            s3_client=s3_client,
            with_default_file_name="do_not_delete.txt",
        )
        logger.info("Recreated incoming: %s", home_directory)
    else:
        for mapping_key in HOME_DIRECTORY_TO_FOLDERS_MAPPING.keys():
            if re.match(
                rf"{mapping_key}",
                home_directory,
            ):
                for folder in HOME_DIRECTORY_TO_FOLDERS_MAPPING[mapping_key]:
                    create_folder_in_s3(
                        bucket_name=bucket_name,
                        folder_path=f'{home_directory}/{folder}/',
                        s3_client=s3_client,
                    )
        if re.match(rf"{SFTP_COMPANY_PREFIX_REGEX}", home_directory) and re.match(
            rf"{SFTP_COMPANY_TYPE_SUFFIX_REGEX}",
            home_directory,
        ):
            for folder in COMPANY_FOLDERS:
                create_folder_in_s3(
                    bucket_name=bucket_name,
                    folder_path=f'{home_directory}/{folder}/',
                    s3_client=s3_client,
                )
            for folder in INCOMING_FOLDERS:
                create_folder_in_s3(
                    bucket_name=bucket_name,
                    folder_path=f'{home_directory}/{folder}',
                    s3_client=s3_client,
                    with_default_file_name="do_not_delete.txt",
                )

    logger.info("End of on-boarding the: %s", home_directory)
