"""SQL injection detection."""

import re
from typing import Dict, Any, Optional
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class SQLInjectionDetector:
    """Detect SQL injection attacks."""
    
    def __init__(self):
        """Initialize SQL injection detector."""
        self.patterns = [
            rb"(?i)(union\s+select)",
            rb"(?i)(drop\s+table)",
            rb"(?i)(insert\s+into)",
            rb"(?i)(delete\s+from)",
            rb"(?i)(or\s+1\s*=\s*1)",
            rb"(?i)(--\s|#)",
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]
    
    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect SQL injection in packet."""
        payload = packet.get("payload", b"")
        
        for pattern in self.compiled_patterns:
            if pattern.search(payload):
                logger.warning("SQL injection detected", src_ip=packet.get("src_ip"))
                return {
                    "detected": True,
                    "threat_score": 0.9,
                    "type": "sql_injection",
                }
        
        return None

