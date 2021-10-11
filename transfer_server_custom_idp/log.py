import logging
from typing import Optional

import sentry_sdk
import structlog
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration


def create_logger(
    environment: str,
    sentry_dsn: Optional[str],
) -> structlog.BoundLogger:
    """Create a logger."""
    if sentry_dsn:
        sentry_sdk.init(
            dsn=sentry_dsn,
            integrations=[AwsLambdaIntegration()],
            environment=environment,
            sample_rate=1.0,
        )

    logging.basicConfig()

    structlog.configure(
        logger_factory=structlog.stdlib.LoggerFactory(),
        processors=[structlog.processors.JSONRenderer()],
    )

    return structlog.get_logger()
