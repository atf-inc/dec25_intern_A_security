"""Path Traversal Detection Module."""

import re
from typing import Dict, Any, Optional
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class PathTraversalDetector:
    """Detect Path Traversal attacks."""
    
    def __init__(self):
        """Initialize Path Traversal detector."""
        self.patterns = [
            # Standard .. traversal
            rb"(?i)(\.\./|\.\.\\)",
            # URL encoded traversal
            rb"(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)",
            # Double URI encoding
            rb"(?i)(%252e%252e%252f|%252e%252e%255c)",
            # Unicode/UTF-8 variants
            rb"(?i)(\xc0\xae|\xc0\xaf|\xe0\x80\xaf|\xf0\x80\x80\xaf)", # Overlong encoding examples
            # Absolute paths (Linux/Windows)
            rb"(?i)(^/etc/|^/var/|^/home/|^/usr/|^c:\\|^d:\\)",
            rb"(?i)(file:///|file://localhost/)",
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]

    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Path Traversal in packet."""
        payload = packet.get("payload", b"")
        if not payload:
            return None
            
        for pattern in self.compiled_patterns:
            if pattern.search(payload):
                logger.warning("Path Traversal detected", src_ip=packet.get("src_ip"))
                return {
                    "detected": True,
                    "threat_score": 0.85,
                    "type": "path_traversal",
                }
        
        return None
