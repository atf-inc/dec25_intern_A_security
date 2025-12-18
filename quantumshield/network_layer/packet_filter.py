"""
Packet Filter Module.
Detects structural anomalies, malformed packets, and logic attacks.
"""

from typing import Dict, Any, Optional
from ..config.logging_config import get_logger

logger = get_logger(__name__)

class PacketFilter:
    """Stateless packet validation and anomaly detection."""
    
    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect packet anomalies."""
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")
        flags = packet.get("flags", [])
        protocol = packet.get("protocol")
        header_len = packet.get("header_len", 20) # Approx IP header
        payload_len = len(packet.get("payload", b""))
        
        # 1. Land Attack (Src == Dst)
        if src_ip == dst_ip and src_port == dst_port:
             return self._alert("land_attack", "Land Attack: Source equals Destination", 1.0)
             
        # 2. Invalid TCP Flags
        if protocol == "TCP":
            # SYN + FIN
            if 'S' in flags and 'F' in flags:
                 return self._alert("invalid_flags", "Illegal Flag Combo: SYN+FIN", 0.9)
            # SYN + RST
            if 'S' in flags and 'R' in flags:
                  return self._alert("invalid_flags", "Illegal Flag Combo: SYN+RST", 0.9)
            # FIN + RST
            if 'F' in flags and 'R' in flags:
                  return self._alert("invalid_flags", "Illegal Flag Combo: FIN+RST", 0.9)

        # 3. Teardrop (Fragment Offset Check)
        # Note: Scapy usually abstracts reassembly, but if we got raw fragment info:
        # For this scope, we simulate check if "frag_offset" is present
        # This is hard to do without raw packet fragmentation data matching
        pass
        
        # 4. Malformed Packets
        # E.g., Header length < 20 (IP)
        if header_len < 20: 
             return self._alert("malformed_packet", "Invalid IP Header Length", 0.8)
             
        return None

    def _alert(self, type_name: str, reason: str, score: float) -> Dict[str, Any]:
        return {
            "detected": True,
            "type": type_name,
            "severity": "high",
            "threat_score": score,
            "reason": reason
        }
