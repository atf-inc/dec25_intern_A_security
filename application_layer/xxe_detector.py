"""XXE (XML External Entity) Detection Module."""

import re
from typing import Dict, Any, Optional
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class XXEDetector:
    """Detect XXE attacks."""
    
    def __init__(self):
        """Initialize XXE detector."""
        self.patterns = [
            # Basic Entity Definition
            rb"(?i)(<!ENTITY\s+)",
            rb"(?i)(<!DOCTYPE\s+)",
            rb"(?i)(<!DOCTYPE[^>]+)",
            # System/Public identifiers
            rb"(?i)(SYSTEM\s+['\"]|PUBLIC\s+['\"])",
            rb"(?i)(SYSTEM\s+)",
            # Common file protocols in XXE
            rb"(?i)(file:///|http://|https://|ftp://|gopher://|expect://|php://)",
            # Parameter Entities
            rb"(?i)(%\s+\w+\s*;)",
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]

    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect XXE in packet."""
        payload = packet.get("payload", b"")
        if not payload:
            return None
            
        # Optimization: Only check if payload looks like XML
        if b'<' in payload or b'%3C' in payload or b'%3c' in payload:
            for pattern in self.compiled_patterns:
                if pattern.search(payload):
                    logger.warning("XXE detected", src_ip=packet.get("src_ip"))
                    return {
                        "detected": True,
                        "threat_score": 0.9,
                        "type": "xxe_injection",
                    }
        
        return None
