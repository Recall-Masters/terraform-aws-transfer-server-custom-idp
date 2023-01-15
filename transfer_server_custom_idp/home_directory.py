from jinja2 import Template, StrictUndefined

from transfer_server_custom_idp.models.secret_model import Secret


def generate_home_directory(
    template: str,
    secret: Secret,
) -> str:
    """
    Generate the home path for the user.

    This function is currently hard code. Later, it should be replaced with a
    dynamic Jinja2 template supplied as a Terraform module parameter (and then
    as a Lambda function environment variable).

    :param template: Jinja2 template to render the path;
    :param secret: User parameters from AWS Secrets Manager.
    :return: Full absolute path in the format AWS Transfer can understand.
    """
    return (
        Template(
            template,
            lstrip_blocks=True,
            trim_blocks=True,
            keep_trailing_newline=False,
            undefined=StrictUndefined,
        )
        .render(
            secret=secret,
        )
        .strip()
    )[:-1]


def generate_absolute_path(home_directory: str, bucket_name: str) -> str:
    """
    Generate absolute S3 path in the format that SFTP Transfer accepts.

    :param bucket_name: bucket;
    :param home_directory: directory in the bucket.
    :return: path.
    """
    return f"/{bucket_name}/{home_directory}"
