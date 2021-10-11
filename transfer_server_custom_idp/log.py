import logging
import sys
from typing import Optional

import sentry_sdk
import structlog
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration


def create_logger(
    environment: str,
    sentry_dsn: Optional[str],
) -> structlog.stdlib.BoundLogger:
    """Create a logger."""
    if sentry_dsn:
        sentry_sdk.init(
            dsn=sentry_dsn,
            integrations=[AwsLambdaIntegration()],
            environment=environment,
            sample_rate=1.0,
        )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.render_to_log_kwargs,

            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    return structlog.get_logger()
