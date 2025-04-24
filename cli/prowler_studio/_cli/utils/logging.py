import sys
from typing import Literal

from loguru import logger


def set_app_log_level(
    log_level: Literal[
        "TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"
    ],
) -> None:
    """Set the minimum log level for the application.

    This function updates the logger to direct log output to a custom log capturing object,
    filtering logs based on the provided `log_level`. Logs below the specified level will not be shown.

    Args:
        log_level: The minimum level of logs to display. The available levels are:
            - "TRACE"
            - "DEBUG"
            - "INFO"
            - "SUCCESS"
            - "WARNING"
            - "ERROR"
            - "CRITICAL"
        log_capture: An instance of the custom log capture object
    Raises:
        ValueError: If the provided log level is invalid.
    """

    valid_log_levels = {
        "TRACE",
        "DEBUG",
        "INFO",
        "SUCCESS",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }
    if log_level not in valid_log_levels:
        raise ValueError(
            f"Invalid log level: {log_level}. Valid options are: {', '.join(valid_log_levels)}"
        )

    # Remove existing log handlers and set the new log level
    logger.remove()
    logger.add(
        sys.stderr, level=log_level
    )  # TODO: Use a custom log handler object passed as an argument, https://loguru.readthedocs.io/en/stable/resources/recipes.html#capturing-standard-stdout-stderr-and-warnings. Probably cosole prints should be set in this custom handler class, it should be used as view in MVC pattern
