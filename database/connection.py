"""Database connection management."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typing import Optional
import structlog
from ..config.settings import get_settings
from ..config.logging_config import get_logger

logger = get_logger(__name__)

_engine = None
_SessionLocal = None


def get_engine():
    """Get database engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(settings.database_url)
    return _engine


def get_session():
    """Get database session."""
    global _SessionLocal
    if _SessionLocal is None:
        engine = get_engine()
        _SessionLocal = sessionmaker(bind=engine)
    return _SessionLocal()

