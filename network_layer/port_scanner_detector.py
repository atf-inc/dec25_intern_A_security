"""Port scanner detection."""

from typing import Dict, Any
from collections import defaultdict
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class PortScannerDetector:
    """Detect port scanning activity."""
    
    def __init__(self):
        """Initialize port scanner detector."""
        self.scan_attempts: Dict[str, set] = defaultdict(set)
        self.threshold = 10  # ports per IP
    
    def detect(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Detect port scanning."""
        src_ip = packet.get("src_ip", "unknown")
        dst_port = packet.get("dst_port", 0)
        
        self.scan_attempts[src_ip].add(dst_port)
        
        if len(self.scan_attempts[src_ip]) > self.threshold:
            logger.warning("Port scanning detected", src_ip=src_ip)
            return {
                "detected": True,
                "threat_score": 0.7,
                "type": "port_scanning",
            }
        
        return {"detected": False}

