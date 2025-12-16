"""Behavioral analysis engine."""

from typing import Dict, Any, Optional
from collections import defaultdict
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class BehavioralEngine:
    """User/Entity Behavior Analytics engine."""
    
    def __init__(self):
        """Initialize behavioral engine."""
        self.entity_profiles: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.connection_patterns: Dict[str, list] = defaultdict(list)
    
    async def initialize(self) -> None:
        """Initialize behavioral engine."""
        logger.info("Initializing behavioral engine")
    
    async def analyze(
        self, packet: Dict[str, Any], flow: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze behavioral patterns.
        
        Returns:
            Dict with threat_score, suspicious, and behavioral_indicators
        """
        src_ip = packet.get("src_ip", "unknown")
        dst_ip = packet.get("dst_ip", "unknown")
        dst_port = packet.get("dst_port", 0)
        timestamp = packet.get("timestamp", 0)
        
        # Update connection patterns
        self.connection_patterns[src_ip].append({
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "timestamp": timestamp,
        })
        
        # Keep only recent connections (last hour)
        recent_connections = [
            conn for conn in self.connection_patterns[src_ip]
            if timestamp - conn["timestamp"] < 3600
        ]
        self.connection_patterns[src_ip] = recent_connections
        
        # Analyze for suspicious behavior
        indicators = []
        threat_score = 0.0
        
        # Check for port scanning
        unique_ports = len(set(conn["dst_port"] for conn in recent_connections))
        if unique_ports > 50:
            indicators.append("port_scanning")
            threat_score = max(threat_score, 0.7)
        
        # Check for horizontal scanning (many different IPs)
        unique_ips = len(set(conn["dst_ip"] for conn in recent_connections))
        if unique_ips > 20:
            indicators.append("horizontal_scanning")
            threat_score = max(threat_score, 0.8)
        
        # Check for rapid connections
        if len(recent_connections) > 100:
            indicators.append("rapid_connections")
            threat_score = max(threat_score, 0.6)
        
        # Check for failed connections (would need connection state tracking)
        # This is simplified - in real implementation, track connection states
        
        if indicators:
            logger.warning(
                "Suspicious behavior detected",
                indicators=indicators,
                src_ip=src_ip,
            )
            
            return {
                "threat_score": threat_score,
                "suspicious": True,
                "behavioral_indicators": indicators,
                "engine": "behavioral",
            }
        
        return {
            "threat_score": 0.0,
            "suspicious": False,
            "engine": "behavioral",
        }

