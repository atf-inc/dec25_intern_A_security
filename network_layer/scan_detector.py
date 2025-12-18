"""
Scan Detection Module.
Detects Port Scanning, IP Sweeping, and Stealth Scans (Xmas, Null).
"""

from typing import Dict, Any, Optional
from ..config.logging_config import get_logger
from .connection_tracker import ConnectionTracker

logger = get_logger(__name__)

class ScanDetector:
    """Detects reconnaissance activities."""
    
    def __init__(self, connection_tracker: ConnectionTracker):
        self.tracker = connection_tracker
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 20 # Distinct ports per minute
        self.IP_SWEEP_THRESHOLD = 20 # Distinct IPs per minute
        
    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Scanning patterns."""
        src_ip = packet.get("src_ip")
        flags = packet.get("flags", [])
        protocol = packet.get("protocol")
        
        if not src_ip:
            return None

        # 1. Stealth Scans (Invalid Flag Combinations)
        if protocol == "TCP":
            # Null Scan
            if not flags:
                return self._alert("null_scan", "TCP Null Scan detected (No flags)", 0.8)
                
            # Xmas Scan (FIN, URG, PSH)
            if 'F' in flags and 'U' in flags and 'P' in flags:
                return self._alert("xmas_scan", "TCP Xmas Tree Scan detected", 0.9)
                
            # FIN Scan (FIN only to open port usually dropped, closed sends RST)
            # Hard to detect without context, but strictly speaking unexpected if no connection
            pass

        # 2. Behavioral Scanning (using Tracker)
        host_state = self.tracker.get_host_state(src_ip)
        if host_state:
            # Port Scan Check
            if len(host_state.ports_scanned) > self.PORT_SCAN_THRESHOLD:
                # Calculate speed could be added too
                 return self._alert(
                     "port_scan", 
                     f"Port Scan: {len(host_state.ports_scanned)} ports accessed", 
                     0.7
                 )
            
            # IP Sweep Check
            if len(host_state.dest_ips_contacted) > self.IP_SWEEP_THRESHOLD:
                return self._alert(
                     "ip_sweep", 
                     f"IP Sweep: {len(host_state.dest_ips_contacted)} hosts contacted", 
                     0.7
                 )
        
        return None

    def _alert(self, type_name: str, reason: str, score: float) -> Dict[str, Any]:
        return {
            "detected": True,
            "type": type_name,
            "severity": "medium",
            "threat_score": score,
            "reason": reason
        }
