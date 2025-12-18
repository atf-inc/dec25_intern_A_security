"""
Configuration package for QuantumShield.

Currently exposes:
- get_settings (from .settings)
"""

from .settings import get_settings, Settings

__all__ = ["get_settings", "Settings"]


