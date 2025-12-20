"""
Central logging configuration for QuantumShield.

Provides:
- setup_logging(level: str = "INFO")
- get_logger(name: str)
"""

from __future__ import annotations

import logging
from logging.config import dictConfig

import structlog


def setup_logging(level: str = "INFO") -> None:
    """Configure standard logging and structlog."""

    log_level = getattr(logging, level.upper(), logging.INFO)

    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "plain": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                },
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "plain",
                    "level": log_level,
                }
            },
            "root": {
                "handlers": ["console"],
                "level": log_level,
            },
        }
    )

    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str):
    """
    Return a structlog logger bound to the given name.

    Modules that import this function expect a callable returning a
    logger with the standard logging API.
    """

    return structlog.get_logger(name)



