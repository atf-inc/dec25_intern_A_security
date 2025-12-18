"""
Connection Tracker Module.
Tracks the state of network connections for stateful analysis.
"""

import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from ..config.logging_config import get_logger

logger = get_logger(__name__)

@dataclass
class ConnectionState:
    """State of a specific connection (flow)."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    flags_seen: List[str] = field(default_factory=list)
    state: str = "NEW"  # NEW, ESTABLISHED, CLOSED
    
    # For heuristics
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    
    def update(self, packet_size: int, flags: List[str]):
        """Update connection state with new packet info."""
        self.last_seen = time.time()
        self.packet_count += 1
        self.byte_count += packet_size
        self.flags_seen.extend(flags)
        
        # Simple TCP State Machine (heuristic)
        if 'S' in flags: # SYN
            self.syn_count += 1
            if self.state == "NEW":
                self.state = "SYN_SENT"
        if 'A' in flags: # ACK
            self.ack_count += 1
            if self.state == "SYN_SENT":
                self.state = "ESTABLISHED"
        if 'F' in flags: # FIN
            self.fin_count += 1
            self.state = "CLOSING"
        if 'R' in flags: # RST
            self.rst_count += 1
            self.state = "RESET"

@dataclass
class HostState:
    """State tracking for a source IP (for scanning detection)."""
    ip: str
    ports_scanned: set = field(default_factory=set)
    dest_ips_contacted: set = field(default_factory=set)
    failed_logins: int = 0
    last_reset: float = field(default_factory=time.time)
    
    def update_scan(self, dst_ip: str, dst_port: int):
        self.ports_scanned.add(dst_port)
        self.dest_ips_contacted.add(dst_ip)
    
    def reset_if_expired(self, window: int = 60):
        if time.time() - self.last_reset > window:
            self.ports_scanned.clear()
            self.dest_ips_contacted.clear()
            self.failed_logins = 0
            self.last_reset = time.time()

class ConnectionTracker:
    """Tracks active connections and host behaviors."""
    
    def __init__(self, cleanup_interval: int = 60, timeout: int = 300):
        self.connections: Dict[str, ConnectionState] = {}
        self.hosts: Dict[str, HostState] = defaultdict(lambda: HostState(ip=""))
        self.cleanup_interval = cleanup_interval
        self.timeout = timeout
        self.last_cleanup = time.time()
        
    def _get_flow_key(self, src_ip, src_port, dst_ip, dst_port, protocol) -> str:
        """Create a unique key for the flow (canonical)."""
        # Canonicalize direction to track full conversation
        if src_ip < dst_ip:
            return f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{protocol}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"

    def track_packet(self, packet_info: Dict[str, Any]) -> ConnectionState:
        """Process a packet and update state."""
        self._cleanup_if_needed()
        
        src_ip = packet_info.get("src_ip", "0.0.0.0")
        dst_ip = packet_info.get("dst_ip", "0.0.0.0")
        src_port = packet_info.get("src_port", 0)
        dst_port = packet_info.get("dst_port", 0)
        protocol = packet_info.get("protocol", "UNKNOWN")
        flags = packet_info.get("flags", [])
        size = packet_info.get("size", 0)
        
        # 1. Update Connection State
        flow_key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)
        
        if flow_key not in self.connections:
            self.connections[flow_key] = ConnectionState(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=protocol,
                start_time=time.time(),
                last_seen=time.time()
            )
        
        conn = self.connections[flow_key]
        conn.update(size, flags)
        
        # 2. Update Host State (Source IP behavior)
        # Ensure host object exists and has IP set
        if src_ip not in self.hosts:
             self.hosts[src_ip].ip = src_ip
             
        host = self.hosts[src_ip]
        host.reset_if_expired()
        host.update_scan(dst_ip, dst_port)
        
        return conn

    def get_host_state(self, ip: str) -> Optional[HostState]:
        return self.hosts.get(ip)

    def _cleanup_if_needed(self):
        """Remove old connections."""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return
            
        # Remove timed out connections
        keys_to_remove = []
        for key, conn in self.connections.items():
            if now - conn.last_seen > self.timeout:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.connections[key]
            
        self.last_cleanup = now
