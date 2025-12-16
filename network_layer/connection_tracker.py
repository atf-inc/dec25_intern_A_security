"""Stateful connection tracking."""

from typing import Dict, Any
from collections import defaultdict
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class ConnectionTracker:
    """Track network connections statefully."""
    
    def __init__(self):
        """Initialize connection tracker."""
        self.connections: Dict[str, Dict[str, Any]] = {}
    
    def update_connection(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Update connection state."""
        flow_key = self._get_flow_key(packet)
        
        if flow_key not in self.connections:
            self.connections[flow_key] = {
                "state": "NEW",
                "packet_count": 0,
                "byte_count": 0,
            }
        
        conn = self.connections[flow_key]
        conn["packet_count"] += 1
        conn["byte_count"] += packet.get("length", 0)
        
        # Update state based on TCP flags
        flags = packet.get("flags", 0)
        if flags & 0x02:  # SYN
            conn["state"] = "SYN_SENT"
        elif flags & 0x10:  # ACK
            conn["state"] = "ESTABLISHED"
        elif flags & 0x01:  # FIN
            conn["state"] = "CLOSING"
        
        return conn
    
    def _get_flow_key(self, packet: Dict[str, Any]) -> str:
        """Generate flow key."""
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)
        protocol = packet.get("protocol", 0)
        
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

