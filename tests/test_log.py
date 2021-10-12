import os

from transfer_server_custom_idp.log import create_logger


def test_log():
    logger = create_logger(
        sentry_dsn=None,
        environment=os.getenv('DEV'),
    )

    logger.warning('It Works!', foo='bar')
