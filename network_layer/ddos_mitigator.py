"""DDoS attack mitigation."""

from typing import Dict, Any
from collections import defaultdict
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class DDoSMitigator:
    """Detect and mitigate DDoS attacks."""
    
    def __init__(self):
        """Initialize DDoS mitigator."""
        self.traffic_stats: Dict[str, list] = defaultdict(list)
        self.threshold_packets_per_second = 1000
    
    def check_ddos(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Check if traffic indicates DDoS."""
        dst_ip = packet.get("dst_ip", "unknown")
        timestamp = packet.get("timestamp", 0)
        
        # Track traffic to destination
        self.traffic_stats[dst_ip].append(timestamp)
        
        # Keep only recent timestamps (last minute)
        recent = [ts for ts in self.traffic_stats[dst_ip] if timestamp - ts < 60]
        self.traffic_stats[dst_ip] = recent
        
        # Check threshold
        pps = len(recent)
        is_ddos = pps > self.threshold_packets_per_second
        
        if is_ddos:
            logger.warning("DDoS detected", dst_ip=dst_ip, pps=pps)
        
        return {
            "is_ddos": is_ddos,
            "packets_per_second": pps,
            "dst_ip": dst_ip,
        }

