"""
API package for QuantumShield.

Exposes the FastAPI app instance from `rest_api`.
"""

from .rest_api import app

__all__ = ["app"]


