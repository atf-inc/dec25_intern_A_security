"""
Application settings for QuantumShield.

This is a lightweight Pydantic-based configuration layer that provides
defaults suitable for local development and testing.
"""

from __future__ import annotations

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Global application settings."""

    # Database
    database_url: str = "sqlite:///./quantumshield.db"

    class Config:
        env_prefix = "QUANTUMSHIELD_"
        case_sensitive = False
    
    # Proxy
    proxy_target: str = "http://localhost:3000"
    proxy_port: int = 8000
    honeypot_url: str = "http://localhost:8001"
    dvwa_url: str = "http://localhost:3000"

    # ML Models
    ml_models_path: str = "models"
    ml_enable_gpu: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance."""

    return Settings()



