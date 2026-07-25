import logging

from sentinel.config import get_settings


def configure_logging() -> None:
    """Configure application-wide logging."""

    settings = get_settings()

    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        ),
    )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger for a SentinelAI module."""

    return logging.getLogger(name)