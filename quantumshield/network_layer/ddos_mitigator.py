"""
DDoS Mitigation Module.
Detects and mitigates SYN Flood, UDP Flood, ICMP Flood, and other DoS attacks.
"""

import time
from typing import Dict, Any, Optional
from ..config.logging_config import get_logger
from .connection_tracker import ConnectionTracker

logger = get_logger(__name__)

class DDoSMitigator:
    """Detects and mitigates DDoS attacks."""
    
    def __init__(self, connection_tracker: ConnectionTracker):
        self.tracker = connection_tracker
        
        # Thresholds (Configurable)
        self.SYN_FLOOD_THRESHOLD = 100 # SYNs per minute without established
        self.UDP_FLOOD_PPS_THRESHOLD = 1000 # Packets per second
        self.ICMP_FLOOD_PPS_THRESHOLD = 200 # Packets per second
        
        # History for rate limiting
        self.packet_counts: Dict[str, int] = {} # Key -> Count
        self.last_reset = time.time()
        
    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect DoS patterns in packet."""
        src_ip = packet.get("src_ip")
        protocol = packet.get("protocol")
        flags = packet.get("flags", [])
        
        if not src_ip:
            return None
            
        # 1. Rate Limiting Check (Simple PPS)
        self._update_rate_limit(src_ip)
        current_rate = self.packet_counts.get(src_ip, 0)
        
        # UDP Flood
        if protocol == "UDP" and current_rate > self.UDP_FLOOD_PPS_THRESHOLD:
            return {
                "detected": True,
                "type": "udp_flood",
                "severity": "critical",
                "threat_score": 0.95,
                "reason": f"High UDP PPS: {current_rate} from {src_ip}"
            }

        # ICMP Flood
        if protocol == "ICMP" and current_rate > self.ICMP_FLOOD_PPS_THRESHOLD:
             return {
                "detected": True,
                "type": "icmp_flood",
                "severity": "medium",
                "threat_score": 0.85,
                "reason": f"High ICMP PPS: {current_rate} from {src_ip}"
            }
            
        # 2. SYN Flood Check (Stateful)
        if protocol == "TCP" and 'S' in flags and 'A' not in flags:
            host_state = self.tracker.get_host_state(src_ip) # Actually need connection stats
            # For SYN flood, we look at ratio of SYN vs ESTABLISHED in tracker?
            # Or simpler: rate of SYNs from a single IP?
            
            # Using HostState heuristic from tracker (assuming it tracks flows)
            # Let's count active NEW connections for this IP
            open_connections = 0
            for conn in self.tracker.connections.values():
                if conn.src_ip == src_ip and conn.state == "SYN_SENT":
                    open_connections += 1
            
            if open_connections > self.SYN_FLOOD_THRESHOLD:
                 return {
                    "detected": True,
                    "type": "syn_flood",
                    "severity": "critical",
                    "threat_score": 1.0,
                    "reason": f"SYN Flood: {open_connections} half-open connections"
                }
        
        # 3. Smurf Attack (Broadcast Check)
        dst_ip = packet.get("dst_ip", "")
        if protocol == "ICMP" and (dst_ip.endswith(".255") or dst_ip == "255.255.255.255"):
             return {
                "detected": True,
                "type": "smurf_attack",
                "severity": "high",
                "threat_score": 0.9,
                "reason": "ICMP packet to broadcast address"
            }

        return None

    def _update_rate_limit(self, ip: str):
        """Reset counters every second."""
        now = time.time()
        if now - self.last_reset > 1.0:
            self.packet_counts.clear()
            self.last_reset = now
        
        self.packet_counts[ip] = self.packet_counts.get(ip, 0) + 1
