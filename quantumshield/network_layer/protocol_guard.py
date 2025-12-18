"""
Protocol Guard Module.
Detects Tunneling, Brute Force, and Protocol abuse.
"""

from typing import Dict, Any, Optional
from ..config.logging_config import get_logger

logger = get_logger(__name__)

class ProtocolGuard:
    """Advanced protocol threat detection."""
    
    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect protocol specific threats."""
        protocol = packet.get("protocol")
        payload = packet.get("payload", b"")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")
        
        # 1. ICMP Tunneling
        # Ping requests (Type 8) usually have small, fixed payloads. 
        # Large payloads or suspicious data suggests usage for data exfiltration.
        if protocol == "ICMP" and len(payload) > 100:
             return self._alert("icmp_tunneling", f"Suspicious ICMP Payload Size: {len(payload)} bytes", 0.85)
             
        # 2. DNS Tunneling logic
        # Usually requires parsing DNS query names (e.g. looking for long subdomains)
        # Assuming payload might contain raw DNS packet, we can do a heuristic check
        # High entropy or length check on UDP/53
        if protocol == "UDP" and (src_port == 53 or dst_port == 53):
            if len(payload) > 300: # Standard DNS queries are usually small
                return self._alert("dns_tunneling", "Large DNS Packet (potential tunneling)", 0.6)
                
        # 3. SSL Stripping / Plaintext passwords
        # Check for unencrypted traffic on 80 that looks like sensitive data
        if protocol == "TCP" and dst_port == 80:
             if b'Authorization: Basic' in payload:
                 return self._alert("insecure_auth", "Basic Auth over cleartext HTTP", 0.9)
             if b'passwd=' in payload or b'password=' in payload:
                 return self._alert("cleartext_creds", "Credentials sent over cleartext", 1.0)
        
        return None

    def _alert(self, type_name: str, reason: str, score: float) -> Dict[str, Any]:
        return {
            "detected": True,
            "type": type_name,
            "severity": "critical",
            "threat_score": score,
            "reason": reason
        }
