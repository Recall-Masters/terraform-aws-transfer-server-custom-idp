import json
import os

from transfer_server_custom_idp.auth import construct_response
from transfer_server_custom_idp.log import create_logger
from transfer_server_custom_idp.models.secret_model import Login


def lambda_handler(event, _context):
    """
    Lambda entry point.

    Construct the response and return it. Catch errors and make sure they reach
    Sentry.
    """
    home_directory_template = os.getenv("HOME_DIRECTORY_TEMPLATE")
    bucket_name = os.getenv("BUCKET_NAME")

    login = Login(**event)

    logger = create_logger(
        sentry_dsn=os.getenv("SENTRY_DSN"),
        environment=os.getenv("ENV"),
    ).bind(
        username=login.username,
        server_id=login.server_id,
        bucket_name=bucket_name,
    )

    try:
        response = construct_response(
            login=login,
            bucket_name=bucket_name,
            home_directory_template=home_directory_template,
            logger=logger,
        )
        logger.info(
            "The response '%s' was successfully constructed for user '%s'",
            login.username,
            json.dumps(response),
        )
        return response
    except Exception as err:
        logger.exception(
            "Authentication failed",
            error_type=err.__class__.__name__,
        )

    return {}
