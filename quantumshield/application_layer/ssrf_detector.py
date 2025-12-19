"""SSRF (Server Side Request Forgery) Detection Module."""

import re
from typing import Dict, Any, Optional
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class SSRFDetector:
    """Detect SSRF attacks."""
    
    def __init__(self):
        """Initialize SSRF detector."""
        self.patterns = [
            # Metadata services
            rb"(?i)(169\.254\.169\.254)", # AWS/Cloud metadata
            rb"(?i)(metadata\.google\.internal)",
            # Localhost / Private IPs
            rb"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
            # Internal ranges (Basic check, can be refined)
            rb"(?i)(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            # Dangerous Protocols
            rb"(?i)(gopher://|dict://|file://|ldap://|tftp://)",
            # URL Encoded variations
            rb"(?i)(%31%36%39\.%32%35%34\.%31%36%39\.%32%35%34)", # Encoded metadata IP
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]

    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect SSRF in packet."""
        payload = packet.get("payload", b"")
        if not payload:
            return None
            
        for pattern in self.compiled_patterns:
            if pattern.search(payload):
                logger.warning("SSRF detected", src_ip=packet.get("src_ip"))
                return {
                    "detected": True,
                    "threat_score": 0.8,
                    "type": "ssrf",
                }
        
        return None
