import boto3


def s3_path_existence_check(
    bucket_name: str,
    path: str,
) -> bool:
    s3_client = boto3.client('s3')
    path_content = s3_client.list_objects(
        Bucket=bucket_name,
        Prefix=path,
        MaxKeys=1,
    )['Content']
    if len(path_content) > 0:
        return True
    return False


def create_folder_in_s3(
    bucket_name: str,
    folder_path: str,
) -> None:
    s3_client = boto3.client('s3')
    s3_client.put_object(
        Bucket=bucket_name,
        Body='',
        Key=folder_path,
    )
