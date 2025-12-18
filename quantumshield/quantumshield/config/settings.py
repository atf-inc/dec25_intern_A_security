"""
Global Configuration Settings for QuantumShield
"""
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic_settings import BaseSettings
from pydantic import Field, validator
from enum import Enum
import yaml
import json


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class DatabaseSettings(BaseSettings):
    """Database configuration"""
    host: str = Field(default="localhost", env="DB_HOST")
    port: int = Field(default=5432, env="DB_PORT")
    name: str = Field(default="quantumshield", env="DB_NAME")
    user: str = Field(default="quantum", env="DB_USER")
    password: str = Field(default="", env="DB_PASSWORD")
    pool_size: int = Field(default=10, env="DB_POOL_SIZE")
    
    @property
    def url(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
    
    @property
    def async_url(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class RedisSettings(BaseSettings):
    """Redis configuration"""
    host: str = Field(default="localhost", env="REDIS_HOST")
    port: int = Field(default=6379, env="REDIS_PORT")
    password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    db: int = Field(default=0, env="REDIS_DB")
    
    @property
    def url(self) -> str:
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"


class MLSettings(BaseSettings):
    """Machine Learning configuration"""
    models_dir: Path = Field(default=Path("models"), env="ML_MODELS_DIR")
    device: str = Field(default="cuda", env="ML_DEVICE")
    batch_size: int = Field(default=32, env="ML_BATCH_SIZE")
    inference_threads: int = Field(default=4, env="ML_INFERENCE_THREADS")
    model_cache_size: int = Field(default=5, env="ML_MODEL_CACHE_SIZE")
    enable_gpu: bool = Field(default=True, env="ML_ENABLE_GPU")
    
    # Model-specific settings
    traffic_classifier_threshold: float = Field(default=0.7, env="ML_TRAFFIC_THRESHOLD")
    anomaly_detector_threshold: float = Field(default=0.8, env="ML_ANOMALY_THRESHOLD")
    ddos_predictor_threshold: float = Field(default=0.75, env="ML_DDOS_THRESHOLD")
    malware_detector_threshold: float = Field(default=0.9, env="ML_MALWARE_THRESHOLD")
    zero_day_threshold: float = Field(default=0.85, env="ML_ZERODAY_THRESHOLD")


class NetworkSettings(BaseSettings):
    """Network configuration"""
    capture_interface: str = Field(default="eth0", env="CAPTURE_INTERFACE")
    promiscuous_mode: bool = Field(default=True, env="PROMISCUOUS_MODE")
    buffer_size: int = Field(default=65536, env="BUFFER_SIZE")
    snap_length: int = Field(default=65535, env="SNAP_LENGTH")
    bpf_filter: str = Field(default="", env="BPF_FILTER")
    queue_size: int = Field(default=10000, env="QUEUE_SIZE")
    worker_threads: int = Field(default=4, env="WORKER_THREADS")


class SecurityToolSettings(BaseSettings):
    """Security tools configuration"""
    suricata_enabled: bool = Field(default=True, env="SURICATA_ENABLED")
    suricata_config_path: Path = Field(
        default=Path("/etc/suricata/suricata.yaml"), 
        env="SURICATA_CONFIG"
    )
    suricata_rules_path: Path = Field(
        default=Path("/etc/suricata/rules"),
        env="SURICATA_RULES"
    )
    
    snort_enabled: bool = Field(default=True, env="SNORT_ENABLED")
    snort_config_path: Path = Field(
        default=Path("/etc/snort/snort.conf"),
        env="SNORT_CONFIG"
    )
    
    zeek_enabled: bool = Field(default=True, env="ZEEK_ENABLED")
    zeek_log_path: Path = Field(
        default=Path("/opt/zeek/logs"),
        env="ZEEK_LOGS"
    )
    
    ossec_enabled: bool = Field(default=True, env="OSSEC_ENABLED")
    ossec_config_path: Path = Field(
        default=Path("/var/ossec/etc/ossec.conf"),
        env="OSSEC_CONFIG"
    )
    
    fail2ban_enabled: bool = Field(default=True, env="FAIL2BAN_ENABLED")
    fail2ban_config_path: Path = Field(
        default=Path("/etc/fail2ban/jail.local"),
        env="FAIL2BAN_CONFIG"
    )
    
    modsecurity_enabled: bool = Field(default=True, env="MODSECURITY_ENABLED")
    modsecurity_config_path: Path = Field(
        default=Path("/etc/modsecurity/modsecurity.conf"),
        env="MODSECURITY_CONFIG"
    )
    
    clamav_enabled: bool = Field(default=True, env="CLAMAV_ENABLED")
    clamav_socket: Path = Field(
        default=Path("/var/run/clamav/clamd.ctl"),
        env="CLAMAV_SOCKET"
    )
    
    ndpi_enabled: bool = Field(default=True, env="NDPI_ENABLED")
    
    wazuh_enabled: bool = Field(default=True, env="WAZUH_ENABLED")
    wazuh_api_url: str = Field(
        default="https://localhost:55000",
        env="WAZUH_API_URL"
    )


class AlertSettings(BaseSettings):
    """Alert configuration"""
    email_enabled: bool = Field(default=True, env="ALERT_EMAIL_ENABLED")
    smtp_host: str = Field(default="localhost", env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_user: str = Field(default="", env="SMTP_USER")
    smtp_password: str = Field(default="", env="SMTP_PASSWORD")
    alert_recipients: List[str] = Field(default=[], env="ALERT_RECIPIENTS")
    
    slack_enabled: bool = Field(default=False, env="ALERT_SLACK_ENABLED")
    slack_webhook: str = Field(default="", env="SLACK_WEBHOOK")
    
    webhook_enabled: bool = Field(default=False, env="ALERT_WEBHOOK_ENABLED")
    webhook_urls: List[str] = Field(default=[], env="WEBHOOK_URLS")
    
    syslog_enabled: bool = Field(default=True, env="SYSLOG_ENABLED")
    syslog_host: str = Field(default="localhost", env="SYSLOG_HOST")
    syslog_port: int = Field(default=514, env="SYSLOG_PORT")


class APISettings(BaseSettings):
    """API configuration"""
    host: str = Field(default="0.0.0.0", env="API_HOST")
    port: int = Field(default=8000, env="API_PORT")
    debug: bool = Field(default=False, env="API_DEBUG")
    secret_key: str = Field(default="change-me-in-production", env="API_SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="TOKEN_EXPIRE_MINUTES")
    cors_origins: List[str] = Field(default=["*"], env="CORS_ORIGINS")
    rate_limit: int = Field(default=100, env="API_RATE_LIMIT")


class Settings(BaseSettings):
    """Main settings class combining all configurations"""
    
    # Environment
    environment: Environment = Field(default=Environment.DEVELOPMENT, env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: LogLevel = Field(default=LogLevel.INFO, env="LOG_LEVEL")
    
    # Paths
    base_dir: Path = Field(default=Path(__file__).parent.parent)
    config_dir: Path = Field(default=Path(__file__).parent)
    logs_dir: Path = Field(default=Path("logs"))
    data_dir: Path = Field(default=Path("datasets"))
    
    # Sub-settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    ml: MLSettings = Field(default_factory=MLSettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    security_tools: SecurityToolSettings = Field(default_factory=SecurityToolSettings)
    alerts: AlertSettings = Field(default_factory=AlertSettings)
    api: APISettings = Field(default_factory=APISettings)
    
    # Performance settings
    max_workers: int = Field(default=8, env="MAX_WORKERS")
    queue_max_size: int = Field(default=100000, env="QUEUE_MAX_SIZE")
    processing_batch_size: int = Field(default=100, env="PROCESSING_BATCH_SIZE")
    
    # Feature flags
    enable_ml_detection: bool = Field(default=True, env="ENABLE_ML_DETECTION")
    enable_signature_detection: bool = Field(default=True, env="ENABLE_SIGNATURE_DETECTION")
    enable_anomaly_detection: bool = Field(default=True, env="ENABLE_ANOMALY_DETECTION")
    enable_behavioral_detection: bool = Field(default=True, env="ENABLE_BEHAVIORAL_DETECTION")
    enable_adaptive_learning: bool = Field(default=True, env="ENABLE_ADAPTIVE_LEARNING")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    @validator('logs_dir', 'data_dir', 'config_dir', pre=True, always=True)
    def ensure_absolute_path(cls, v, values):
        path = Path(v)
        if not path.is_absolute():
            base = values.get('base_dir', Path(__file__).parent.parent)
            path = base / path
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    def load_yaml_config(self, config_name: str) -> Dict:
        """Load a YAML configuration file"""
        config_path = self.config_dir / f"{config_name}.yaml"
        if config_path.exists():
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return {}
    
    def load_json_config(self, config_name: str) -> Dict:
        """Load a JSON configuration file"""
        config_path = self.config_dir / f"{config_name}.json"
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}
    
    def get_tool_config(self, tool_name: str) -> Dict:
        """Get configuration for a specific security tool"""
        return self.load_yaml_config(f"tool_configs/{tool_name}")
    
    def get_policy(self, policy_name: str) -> Dict:
        """Get a policy configuration"""
        return self.load_json_config(f"policies/{policy_name}")


# Singleton instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Reload settings from environment and files"""
    global _settings
    _settings = Settings()
    return _settings
