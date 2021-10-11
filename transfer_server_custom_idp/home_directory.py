from jinja2 import Template, StrictUndefined


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
