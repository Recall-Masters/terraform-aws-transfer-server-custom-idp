import base64

import boto3
from structlog import BoundLogger

from transfer_server_custom_idp.errors import UserNotFound


def get_secret(
    username: str,
    secrets_manager_prefix: str,
    aws_region: str,
    logger: BoundLogger,
):
    """Retrieves user information from AWS Secrets Manager."""
    secret_id = f"{secrets_manager_prefix}/{username}"
    client = boto3.session.Session().client(
        service_name="secretsmanager",
        region_name=aws_region,
    )

    try:
        resp = client.get_secret_value(SecretId=secret_id)
    except client.exceptions.ResourceNotFoundException as err:
        raise UserNotFound(username=username) from err

    # Depending on whether the secret is a string or binary,
    # one of these fields will be populated.
    if "SecretString" in resp:
        logger.info("Found Secret String")
        return resp["SecretString"]
    else:
        logger.info("Found Binary Secret")
        return base64.b64decode(resp["SecretBinary"])
