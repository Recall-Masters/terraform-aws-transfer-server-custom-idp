import logging

from botocore.client import BaseClient

from transfer_server_custom_idp.settings import (
    COMPANY_FOLDERS, HOME_DIRECTORY_TO_FOLDERS_MAPPING,
    SFTP_COMPANY_PREFIX,
)

logger = logging.getLogger(__name__)


def s3_path_existence_check(
    bucket_name: str,
    path: str,
    s3_client: BaseClient,
) -> bool:
    """Checks the existence of path in AWS S3 bucket."""
    logger.info('File path to find: %s', path)
    if s3_client.list_objects(
        Bucket=bucket_name,
        Prefix=path,
        MaxKeys=1,
    ).get('Contents'):
        logger.info("Path is here!")
        return True
    logger.info("Path is not here")
    return False


def create_folder_in_s3(
    bucket_name: str,
    folder_path: str,
    s3_client: BaseClient,
) -> None:
    """Creates path in AWS S3 bucket without object upload."""
    try:
        logger.info("Folder path to create: %s", folder_path)
        s3_client.put_object(
            Bucket=bucket_name,
            Body="",
            Key=folder_path,
        )
    except Exception as error:
        logger.info("Exception occurred: %s", error)
        raise Exception


def onboard_new_user_with_home_directory_folders_in_s3(
    home_directory: str,
    bucket_name: str,
    s3_client: BaseClient,
) -> None:
    """Creates the home directory folders based on home directory prefix."""
    logger.info("Onboard the: %s", home_directory)
    for mapping_key in HOME_DIRECTORY_TO_FOLDERS_MAPPING.keys():
        if mapping_key in home_directory:
            for folder in HOME_DIRECTORY_TO_FOLDERS_MAPPING[mapping_key]:
                create_folder_in_s3(
                    bucket_name=bucket_name,
                    folder_path=f"{home_directory}/{folder}/",
                    s3_client=s3_client,
                )
        if SFTP_COMPANY_PREFIX in home_directory:
            for folder in COMPANY_FOLDERS:
                logger.info("Company: %s", f"{home_directory.rsplit('/', 1)[0]}/{folder}/")
                create_folder_in_s3(
                    bucket_name=bucket_name,
                    folder_path=f"{home_directory.rsplit('/', 1)[0]}/{folder}/",
                    s3_client=s3_client,
                )
    logger.info("End of onboard the: %s", home_directory)
