"""XSS detection."""

import re
from typing import Dict, Any, Optional
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class XSSDetector:
    """Detect XSS attacks."""
    
    def __init__(self):
        """Initialize XSS detector."""
        self.patterns = [
            rb"(?i)(<script)",
            rb"(?i)(javascript:)",
            rb"(?i)(onerror=)",
            rb"(?i)(onclick=)",
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]
    
    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect XSS in packet."""
        payload = packet.get("payload", b"")
        
        for pattern in self.compiled_patterns:
            if pattern.search(payload):
                logger.warning("XSS detected", src_ip=packet.get("src_ip"))
                return {
                    "detected": True,
                    "threat_score": 0.8,
                    "type": "xss",
                }
        
        return None

