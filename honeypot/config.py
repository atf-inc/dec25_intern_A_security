import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # Groq API Configuration
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    
    # Database Configuration
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME = os.getenv("DB_NAME", "shadow_guardian")
    
    # Honeypot Configuration
    HONEYPOT_NAME = os.getenv("HONEYPOT_NAME", "QuantumShield")
    SYSTEM_PERSONA = os.getenv("SYSTEM_PERSONA", "Ubuntu 22.04 LTS")
    
    # Rate Limiting Configuration
    RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
    
    # Cache Configuration
    CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))
    CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "1000"))
    
    # LLM Configuration
    LLM_MODEL = os.getenv("LLM_MODEL", "openai/gpt-oss-20b")
    LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "100000"))
    
    # Email Alert Configuration (SendGrid)
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
    ALERT_FROM_EMAIL = os.getenv("ALERT_FROM_EMAIL")
    ALERT_TO_EMAIL = os.getenv("ALERT_TO_EMAIL")
    ENABLE_EMAIL_ALERTS = os.getenv("ENABLE_EMAIL_ALERTS", "true").lower() == "true"
    
    def validate(self):
        """Validate required settings - warnings instead of errors for Cloud Run flexibility"""
        import logging
        logger = logging.getLogger("config")
        
        if not self.GROQ_API_KEY:
            logger.warning("GROQ_API_KEY not set. LLM features will be disabled.")
        
        # Validate email settings if alerts are enabled
        if self.ENABLE_EMAIL_ALERTS:
            if not self.SENDGRID_API_KEY:
                logger.warning("SENDGRID_API_KEY not set. Disabling email alerts.")
                self.ENABLE_EMAIL_ALERTS = False
            if not self.ALERT_FROM_EMAIL:
                logger.warning("ALERT_FROM_EMAIL not set. Disabling email alerts.")
                self.ENABLE_EMAIL_ALERTS = False
            if not self.ALERT_TO_EMAIL:
                logger.warning("ALERT_TO_EMAIL not set. Disabling email alerts.")
                self.ENABLE_EMAIL_ALERTS = False
        
        return True

settings = Settings()
settings.validate()

