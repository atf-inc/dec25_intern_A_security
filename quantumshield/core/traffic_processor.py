#!/usr/bin/env python3
"""
QuantumShield - Traffic Processor Module
Handles traffic preprocessing, flow assembly, and feature extraction
"""

import asyncio
import hashlib
import logging
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import threading
from queue import Queue, Empty
import numpy as np

try:
    from ..network_layer.deep_packet_inspector import DeepPacketInspector
except (ImportError, ValueError):
    # Fallback if running standalone
    try:
        import sys
        import os
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from quantumshield.network_layer.deep_packet_inspector import DeepPacketInspector
    except ImportError:
        DeepPacketInspector = None


try:
    from scapy.all import (
        IP, IPv6, TCP, UDP, ICMP, DNS, HTTP, Raw,
        Ether, ARP
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Define dummy values for when scapy is not available
    IP = None
    IPv6 = None
    TCP = None
    UDP = None
    ICMP = None
    DNS = None
    HTTP = None
    Raw = None
    Ether = None
    ARP = None

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """Network protocol types"""
    UNKNOWN = auto()
    TCP = auto()
    UDP = auto()
    ICMP = auto()
    ICMPV6 = auto()
    DNS = auto()
    HTTP = auto()
    HTTPS = auto()
    SSH = auto()
    FTP = auto()
    SMTP = auto()
    IMAP = auto()
    POP3 = auto()
    TELNET = auto()
    RDP = auto()
    SMB = auto()
    LDAP = auto()
    MYSQL = auto()
    POSTGRESQL = auto()
    MONGODB = auto()
    REDIS = auto()
    ARP = auto()
    DHCP = auto()
    NTP = auto()
    SNMP = auto()
    TLS = auto()
    QUIC = auto()


class FlowDirection(Enum):
    """Direction of traffic flow"""
    FORWARD = auto()
    BACKWARD = auto()
    BIDIRECTIONAL = auto()


class FlowState(Enum):
    """TCP connection state"""
    NEW = auto()
    ESTABLISHED = auto()
    FIN_WAIT = auto()
    CLOSE_WAIT = auto()
    CLOSING = auto()
    TIME_WAIT = auto()
    CLOSED = auto()
    RESET = auto()


@dataclass
class PacketInfo:
    """Parsed packet information"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    ip_version: int
    ttl: int
    ip_len: int
    payload_len: int
    payload: bytes
    flags: Dict[str, bool] = field(default_factory=dict)
    raw_packet: Optional[Any] = None
    
    # TCP specific
    seq_num: int = 0
    ack_num: int = 0
    window_size: int = 0
    
    # Additional metadata
    interface: str = ""
    direction: FlowDirection = FlowDirection.FORWARD
    
    @property
    def flow_key(self) -> str:
        """Generate unique flow identifier"""
        return self._generate_flow_key(
            self.src_ip, self.src_port,
            self.dst_ip, self.dst_port,
            self.protocol.name
        )
    
    @property
    def reverse_flow_key(self) -> str:
        """Generate reverse flow identifier"""
        return self._generate_flow_key(
            self.dst_ip, self.dst_port,
            self.src_ip, self.src_port,
            self.protocol.name
        )
    
    @staticmethod
    def _generate_flow_key(src_ip: str, src_port: int, 
                          dst_ip: str, dst_port: int, 
                          protocol: str) -> str:
        """Generate consistent flow key"""
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return hashlib.md5(key.encode()).hexdigest()[:16]


@dataclass
class FlowStatistics:
    """Statistical features for a flow"""
    # Basic statistics
    packet_count: int = 0
    byte_count: int = 0
    payload_byte_count: int = 0
    
    # Forward direction
    fwd_packet_count: int = 0
    fwd_byte_count: int = 0
    fwd_payload_bytes: int = 0
    
    # Backward direction
    bwd_packet_count: int = 0
    bwd_byte_count: int = 0
    bwd_payload_bytes: int = 0
    
    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    
    # Inter-arrival times
    iat_times: List[float] = field(default_factory=list)
    fwd_iat_times: List[float] = field(default_factory=list)
    bwd_iat_times: List[float] = field(default_factory=list)
    
    # Packet sizes
    packet_sizes: List[int] = field(default_factory=list)
    fwd_packet_sizes: List[int] = field(default_factory=list)
    bwd_packet_sizes: List[int] = field(default_factory=list)
    
    # TCP flags
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    
    # Window sizes
    window_sizes: List[int] = field(default_factory=list)
    
    # TTL values
    ttl_values: List[int] = field(default_factory=list)


@dataclass
class NetworkFlow:
    """Represents a complete network flow"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    state: FlowState = FlowState.NEW
    statistics: FlowStatistics = field(default_factory=FlowStatistics)
    packets: List[PacketInfo] = field(default_factory=list)
    features: Dict[str, float] = field(default_factory=dict)
    labels: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Timing
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Analysis results
    threat_score: float = 0.0
    anomaly_score: float = 0.0
    classification: str = "unknown"
    
    @property
    def is_active(self) -> bool:
        """Check if flow is still active"""
        return self.state in [FlowState.NEW, FlowState.ESTABLISHED]
    
    @property
    def is_complete(self) -> bool:
        """Check if flow has completed"""
        return self.state in [FlowState.CLOSED, FlowState.RESET, FlowState.TIME_WAIT]


class PacketParser:
    """Parse raw packets into structured PacketInfo objects"""
    
    # Well-known ports to protocol mapping
    PORT_PROTOCOLS = {
        20: ProtocolType.FTP,
        21: ProtocolType.FTP,
        22: ProtocolType.SSH,
        23: ProtocolType.TELNET,
        25: ProtocolType.SMTP,
        53: ProtocolType.DNS,
        80: ProtocolType.HTTP,
        110: ProtocolType.POP3,
        143: ProtocolType.IMAP,
        443: ProtocolType.HTTPS,
        445: ProtocolType.SMB,
        389: ProtocolType.LDAP,
        636: ProtocolType.LDAP,
        993: ProtocolType.IMAP,
        995: ProtocolType.POP3,
        1433: ProtocolType.MYSQL,
        1521: ProtocolType.MYSQL,
        3306: ProtocolType.MYSQL,
        3389: ProtocolType.RDP,
        5432: ProtocolType.POSTGRESQL,
        6379: ProtocolType.REDIS,
        27017: ProtocolType.MONGODB,
    }
    
    def __init__(self):
        self.stats = {
            'parsed': 0,
            'failed': 0,
            'by_protocol': defaultdict(int)
        }
    
    def parse_packet(self, packet: Any, timestamp: float = None, 
                    interface: str = "") -> Optional[PacketInfo]:
        """Parse a packet (Scapy packet or raw bytes)"""
        try:
            if timestamp is None:
                timestamp = time.time()
            
            if SCAPY_AVAILABLE and hasattr(packet, 'summary'):  # Scapy packets have summary method
                return self._parse_scapy_packet(packet, timestamp, interface)
                return self._parse_scapy_packet(packet, timestamp, interface)
            elif isinstance(packet, bytes):
                return self._parse_raw_packet(packet, timestamp, interface)
            else:
                logger.warning(f"Unknown packet type: {type(packet)}")
                return None
                
        except Exception as e:
            self.stats['failed'] += 1
            logger.debug(f"Failed to parse packet: {e}")
            return None
    
    def _parse_scapy_packet(self, packet: Any, timestamp: float,
                           interface: str) -> Optional[PacketInfo]:
        """Parse a Scapy packet object"""
        # Extract IP layer
        if IP in packet:
            ip_layer = packet[IP]
            ip_version = 4
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            ip_len = ip_layer.len
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            ip_version = 6
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.hlim
            ip_len = ip_layer.plen + 40
        elif ARP in packet:
            # Handle ARP packets
            arp = packet[ARP]
            return PacketInfo(
                timestamp=timestamp,
                src_ip=arp.psrc,
                dst_ip=arp.pdst,
                src_port=0,
                dst_port=0,
                protocol=ProtocolType.ARP,
                ip_version=4,
                ttl=0,
                ip_len=len(packet),
                payload_len=0,
                payload=b'',
                interface=interface,
                raw_packet=packet
            )
        else:
            return None
        
        # Extract transport layer
        src_port = 0
        dst_port = 0
        seq_num = 0
        ack_num = 0
        window_size = 0
        flags = {}
        payload = b''
        
        if TCP in packet:
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            seq_num = tcp.seq
            ack_num = tcp.ack
            window_size = tcp.window
            
            flags = {
                'SYN': bool(tcp.flags & 0x02),
                'ACK': bool(tcp.flags & 0x10),
                'FIN': bool(tcp.flags & 0x01),
                'RST': bool(tcp.flags & 0x04),
                'PSH': bool(tcp.flags & 0x08),
                'URG': bool(tcp.flags & 0x20),
                'ECE': bool(tcp.flags & 0x40),
                'CWR': bool(tcp.flags & 0x80),
            }
            
            protocol = self._identify_protocol(src_port, dst_port, ProtocolType.TCP)
            
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                
        elif UDP in packet:
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            
            protocol = self._identify_protocol(src_port, dst_port, ProtocolType.UDP)
            
            if Raw in packet:
                payload = bytes(packet[Raw].load)
            
            # Check for DNS
            if DNS in packet:
                protocol = ProtocolType.DNS
                
        elif ICMP in packet:
            protocol = ProtocolType.ICMP
            if Raw in packet:
                payload = bytes(packet[Raw].load)
        else:
            protocol = ProtocolType.UNKNOWN
        
        packet_info = PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            ip_version=ip_version,
            ttl=ttl,
            ip_len=ip_len,
            payload_len=len(payload),
            payload=payload,
            flags=flags,
            seq_num=seq_num,
            ack_num=ack_num,
            window_size=window_size,
            interface=interface,
            raw_packet=packet
        )
        
        self.stats['parsed'] += 1
        self.stats['by_protocol'][protocol.name] += 1
        
        return packet_info
    
    def _parse_raw_packet(self, data: bytes, timestamp: float,
                         interface: str) -> Optional[PacketInfo]:
        """Parse raw packet bytes"""
        if len(data) < 20:
            return None
        
        # Parse Ethernet header if present
        if len(data) >= 14:
            eth_type = struct.unpack('!H', data[12:14])[0]
            if eth_type == 0x0800:  # IPv4
                ip_start = 14
            elif eth_type == 0x86DD:  # IPv6
                ip_start = 14
            else:
                ip_start = 0
        else:
            ip_start = 0
        
        # Parse IP header
        if len(data) < ip_start + 20:
            return None
        
        version = (data[ip_start] >> 4) & 0x0F
        
        if version == 4:
            return self._parse_ipv4(data, ip_start, timestamp, interface)
        elif version == 6:
            return self._parse_ipv6(data, ip_start, timestamp, interface)
        else:
            return None
    
    def _parse_ipv4(self, data: bytes, offset: int, timestamp: float,
                   interface: str) -> Optional[PacketInfo]:
        """Parse IPv4 packet"""
        if len(data) < offset + 20:
            return None
        
        ip_header = data[offset:offset + 20]
        version_ihl = ip_header[0]
        ihl = (version_ihl & 0x0F) * 4
        
        ttl = ip_header[8]
        protocol_num = ip_header[9]
        src_ip = ".".join(str(b) for b in ip_header[12:16])
        dst_ip = ".".join(str(b) for b in ip_header[16:20])
        ip_len = struct.unpack('!H', ip_header[2:4])[0]
        
        transport_offset = offset + ihl
        
        src_port = 0
        dst_port = 0
        flags = {}
        seq_num = 0
        ack_num = 0
        window_size = 0
        payload = b''
        
        if protocol_num == 6:  # TCP
            if len(data) >= transport_offset + 20:
                tcp_header = data[transport_offset:transport_offset + 20]
                src_port = struct.unpack('!H', tcp_header[0:2])[0]
                dst_port = struct.unpack('!H', tcp_header[2:4])[0]
                seq_num = struct.unpack('!I', tcp_header[4:8])[0]
                ack_num = struct.unpack('!I', tcp_header[8:12])[0]
                data_offset = ((tcp_header[12] >> 4) & 0x0F) * 4
                tcp_flags = tcp_header[13]
                window_size = struct.unpack('!H', tcp_header[14:16])[0]
                
                flags = {
                    'FIN': bool(tcp_flags & 0x01),
                    'SYN': bool(tcp_flags & 0x02),
                    'RST': bool(tcp_flags & 0x04),
                    'PSH': bool(tcp_flags & 0x08),
                    'ACK': bool(tcp_flags & 0x10),
                    'URG': bool(tcp_flags & 0x20),
                }
                
                payload_offset = transport_offset + data_offset
                if len(data) > payload_offset:
                    payload = data[payload_offset:]
                
                protocol = self._identify_protocol(src_port, dst_port, ProtocolType.TCP)
            else:
                protocol = ProtocolType.TCP
                
        elif protocol_num == 17:  # UDP
            if len(data) >= transport_offset + 8:
                udp_header = data[transport_offset:transport_offset + 8]
                src_port = struct.unpack('!H', udp_header[0:2])[0]
                dst_port = struct.unpack('!H', udp_header[2:4])[0]
                
                payload_offset = transport_offset + 8
                if len(data) > payload_offset:
                    payload = data[payload_offset:]
                
                protocol = self._identify_protocol(src_port, dst_port, ProtocolType.UDP)
            else:
                protocol = ProtocolType.UDP
                
        elif protocol_num == 1:  # ICMP
            protocol = ProtocolType.ICMP
            if len(data) > transport_offset + 8:
                payload = data[transport_offset + 8:]
        else:
            protocol = ProtocolType.UNKNOWN
        
        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            ip_version=4,
            ttl=ttl,
            ip_len=ip_len,
            payload_len=len(payload),
            payload=payload,
            flags=flags,
            seq_num=seq_num,
            ack_num=ack_num,
            window_size=window_size,
            interface=interface
        )
    
    def _parse_ipv6(self, data: bytes, offset: int, timestamp: float,
                   interface: str) -> Optional[PacketInfo]:
        """Parse IPv6 packet"""
        if len(data) < offset + 40:
            return None
        
        ip_header = data[offset:offset + 40]
        payload_len = struct.unpack('!H', ip_header[4:6])[0]
        next_header = ip_header[6]
        hop_limit = ip_header[7]
        
        src_ip = ":".join(f"{ip_header[8+i*2]:02x}{ip_header[9+i*2]:02x}" 
                         for i in range(8))
        dst_ip = ":".join(f"{ip_header[24+i*2]:02x}{ip_header[25+i*2]:02x}" 
                         for i in range(8))
        
        transport_offset = offset + 40
        
        # Similar parsing for TCP/UDP as IPv4
        src_port = 0
        dst_port = 0
        flags = {}
        payload = b''
        
        if next_header == 6:  # TCP
            protocol = ProtocolType.TCP
        elif next_header == 17:  # UDP
            protocol = ProtocolType.UDP
        elif next_header == 58:  # ICMPv6
            protocol = ProtocolType.ICMPV6
        else:
            protocol = ProtocolType.UNKNOWN
        
        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            ip_version=6,
            ttl=hop_limit,
            ip_len=payload_len + 40,
            payload_len=len(payload),
            payload=payload,
            flags=flags,
            interface=interface
        )
    
    def _identify_protocol(self, src_port: int, dst_port: int,
                          transport: ProtocolType) -> ProtocolType:
        """Identify application protocol based on ports"""
        if src_port in self.PORT_PROTOCOLS:
            return self.PORT_PROTOCOLS[src_port]
        if dst_port in self.PORT_PROTOCOLS:
            return self.PORT_PROTOCOLS[dst_port]
        return transport


class FlowTracker:
    """Track and manage network flows"""
    
    def __init__(self, 
                 flow_timeout: float = 120.0,
                 max_flows: int = 100000,
                 max_packets_per_flow: int = 1000):
        self.flows: Dict[str, NetworkFlow] = {}
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.max_packets_per_flow = max_packets_per_flow
        self.lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'total_flows': 0,
            'active_flows': 0,
            'completed_flows': 0,
            'expired_flows': 0,
            'packets_processed': 0
        }
        
        # Callbacks
        self.on_flow_created: Optional[Callable] = None
        self.on_flow_updated: Optional[Callable] = None
        self.on_flow_completed: Optional[Callable] = None
        self.on_flow_expired: Optional[Callable] = None
    
    def process_packet(self, packet_info: PacketInfo) -> NetworkFlow:
        """Process a packet and update/create flow"""
        with self.lock:
            flow_key = packet_info.flow_key
            reverse_key = packet_info.reverse_flow_key
            
            # Check if flow exists
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                direction = FlowDirection.FORWARD
            elif reverse_key in self.flows:
                flow = self.flows[reverse_key]
                direction = FlowDirection.BACKWARD
            else:
                # Create new flow
                flow = self._create_flow(packet_info)
                self.flows[flow_key] = flow
                direction = FlowDirection.FORWARD
                
                if self.on_flow_created:
                    self.on_flow_created(flow)
            
            # Update flow
            packet_info.direction = direction
            self._update_flow(flow, packet_info, direction)
            
            # Check for flow state changes
            self._update_flow_state(flow, packet_info)
            
            if self.on_flow_updated:
                self.on_flow_updated(flow)
            
            # Check if flow is complete
            if flow.is_complete:
                if self.on_flow_completed:
                    self.on_flow_completed(flow)
            
            self.stats['packets_processed'] += 1
            
            return flow
    
    def _create_flow(self, packet_info: PacketInfo) -> NetworkFlow:
        """Create a new flow from a packet"""
        flow = NetworkFlow(
            flow_id=packet_info.flow_key,
            src_ip=packet_info.src_ip,
            dst_ip=packet_info.dst_ip,
            src_port=packet_info.src_port,
            dst_port=packet_info.dst_port,
            protocol=packet_info.protocol,
            created_at=packet_info.timestamp,
            last_seen=packet_info.timestamp
        )
        
        flow.statistics.start_time = packet_info.timestamp
        
        self.stats['total_flows'] += 1
        self.stats['active_flows'] += 1
        
        return flow
    
    def _update_flow(self, flow: NetworkFlow, packet_info: PacketInfo,
                    direction: FlowDirection):
        """Update flow with new packet information"""
        stats = flow.statistics
        
        # Update timing
        if stats.end_time > 0:
            iat = packet_info.timestamp - stats.end_time
            stats.iat_times.append(iat)
            
            if direction == FlowDirection.FORWARD:
                stats.fwd_iat_times.append(iat)
            else:
                stats.bwd_iat_times.append(iat)
        
        stats.end_time = packet_info.timestamp
        stats.duration = stats.end_time - stats.start_time
        flow.last_seen = packet_info.timestamp
        
        # Update packet counts
        stats.packet_count += 1
        stats.byte_count += packet_info.ip_len
        stats.payload_byte_count += packet_info.payload_len
        
        # Update direction-specific stats
        if direction == FlowDirection.FORWARD:
            stats.fwd_packet_count += 1
            stats.fwd_byte_count += packet_info.ip_len
            stats.fwd_payload_bytes += packet_info.payload_len
            stats.fwd_packet_sizes.append(packet_info.ip_len)
        else:
            stats.bwd_packet_count += 1
            stats.bwd_byte_count += packet_info.ip_len
            stats.bwd_payload_bytes += packet_info.payload_len
            stats.bwd_packet_sizes.append(packet_info.ip_len)
        
        # Update packet sizes
        stats.packet_sizes.append(packet_info.ip_len)
        
        # Update TCP flags
        if packet_info.flags:
            if packet_info.flags.get('SYN'):
                stats.syn_count += 1
            if packet_info.flags.get('ACK'):
                stats.ack_count += 1
            if packet_info.flags.get('FIN'):
                stats.fin_count += 1
            if packet_info.flags.get('RST'):
                stats.rst_count += 1
            if packet_info.flags.get('PSH'):
                stats.psh_count += 1
            if packet_info.flags.get('URG'):
                stats.urg_count += 1
        
        # Update window sizes
        if packet_info.window_size > 0:
            stats.window_sizes.append(packet_info.window_size)
        
        # Update TTL values
        stats.ttl_values.append(packet_info.ttl)
        
        # Store packet (limited)
        if len(flow.packets) < self.max_packets_per_flow:
            flow.packets.append(packet_info)
    
    def _update_flow_state(self, flow: NetworkFlow, packet_info: PacketInfo):
        """Update TCP flow state based on flags"""
        if flow.protocol != ProtocolType.TCP:
            if flow.state == FlowState.NEW:
                flow.state = FlowState.ESTABLISHED
            return
        
        flags = packet_info.flags
        
        if flags.get('RST'):
            flow.state = FlowState.RESET
            self.stats['active_flows'] -= 1
            self.stats['completed_flows'] += 1
            return
        
        if flow.state == FlowState.NEW:
            if flags.get('SYN') and not flags.get('ACK'):
                flow.state = FlowState.NEW
            elif flags.get('SYN') and flags.get('ACK'):
                flow.state = FlowState.ESTABLISHED
        
        elif flow.state == FlowState.ESTABLISHED:
            if flags.get('FIN'):
                flow.state = FlowState.FIN_WAIT
        
        elif flow.state == FlowState.FIN_WAIT:
            if flags.get('FIN'):
                flow.state = FlowState.CLOSING
            elif flags.get('ACK'):
                flow.state = FlowState.CLOSE_WAIT
        
        elif flow.state == FlowState.CLOSING:
            if flags.get('ACK'):
                flow.state = FlowState.TIME_WAIT
        
        elif flow.state == FlowState.CLOSE_WAIT:
            if flags.get('FIN'):
                flow.state = FlowState.CLOSING
    
    def cleanup_expired(self, current_time: float = None) -> List[NetworkFlow]:
        """Remove expired flows"""
        if current_time is None:
            current_time = time.time()
        
        expired = []
        
        with self.lock:
            to_remove = []
            for flow_id, flow in self.flows.items():
                if current_time - flow.last_seen > self.flow_timeout:
                    to_remove.append(flow_id)
                    expired.append(flow)
            
            for flow_id in to_remove:
                del self.flows[flow_id]
                self.stats['expired_flows'] += 1
                self.stats['active_flows'] -= 1
        
        for flow in expired:
            if self.on_flow_expired:
                self.on_flow_expired(flow)
        
        return expired
    
    def get_flow(self, flow_id: str) -> Optional[NetworkFlow]:
        """Get a specific flow by ID"""
        with self.lock:
            return self.flows.get(flow_id)
    
    def get_active_flows(self) -> List[NetworkFlow]:
        """Get all active flows"""
        with self.lock:
            return [f for f in self.flows.values() if f.is_active]
    
    def get_flows_for_ip(self, ip: str) -> List[NetworkFlow]:
        """Get all flows involving a specific IP"""
        with self.lock:
            return [f for f in self.flows.values() 
                   if f.src_ip == ip or f.dst_ip == ip]


class FeatureExtractor:
    """Extract ML features from flows and packets"""
    
    # Feature names for ML models
    FLOW_FEATURE_NAMES = [
        'duration', 'packet_count', 'byte_count', 'payload_byte_count',
        'fwd_packet_count', 'bwd_packet_count', 'fwd_byte_count', 'bwd_byte_count',
        'packets_per_second', 'bytes_per_second',
        'fwd_bwd_packet_ratio', 'fwd_bwd_byte_ratio',
        'min_packet_size', 'max_packet_size', 'mean_packet_size', 'std_packet_size',
        'min_iat', 'max_iat', 'mean_iat', 'std_iat',
        'syn_flag_count', 'ack_flag_count', 'fin_flag_count', 'rst_flag_count',
        'psh_flag_count', 'urg_flag_count',
        'min_window_size', 'max_window_size', 'mean_window_size',
        'min_ttl', 'max_ttl', 'mean_ttl',
        'fwd_min_packet_size', 'fwd_max_packet_size', 'fwd_mean_packet_size',
        'bwd_min_packet_size', 'bwd_max_packet_size', 'bwd_mean_packet_size',
        'fwd_min_iat', 'fwd_max_iat', 'fwd_mean_iat',
        'bwd_min_iat', 'bwd_max_iat', 'bwd_mean_iat',
        'payload_entropy', 'protocol_type', 'is_established',
        'src_port', 'dst_port', 'port_is_well_known',
    ]
    
    def __init__(self):
        self.feature_cache: Dict[str, np.ndarray] = {}
    
    def extract_flow_features(self, flow: NetworkFlow) -> np.ndarray:
        """Extract feature vector from a flow"""
        stats = flow.statistics
        
        # Basic features
        duration = max(stats.duration, 0.001)
        packets_per_second = stats.packet_count / duration
        bytes_per_second = stats.byte_count / duration
        
        # Ratios
        fwd_bwd_packet_ratio = (stats.fwd_packet_count / max(stats.bwd_packet_count, 1))
        fwd_bwd_byte_ratio = (stats.fwd_byte_count / max(stats.bwd_byte_count, 1))
        
        # Packet size statistics
        if stats.packet_sizes:
            min_pkt = min(stats.packet_sizes)
            max_pkt = max(stats.packet_sizes)
            mean_pkt = np.mean(stats.packet_sizes)
            std_pkt = np.std(stats.packet_sizes)
        else:
            min_pkt = max_pkt = mean_pkt = std_pkt = 0
        
        # IAT statistics
        if stats.iat_times:
            min_iat = min(stats.iat_times)
            max_iat = max(stats.iat_times)
            mean_iat = np.mean(stats.iat_times)
            std_iat = np.std(stats.iat_times)
        else:
            min_iat = max_iat = mean_iat = std_iat = 0
        
        # Window size statistics
        if stats.window_sizes:
            min_win = min(stats.window_sizes)
            max_win = max(stats.window_sizes)
            mean_win = np.mean(stats.window_sizes)
        else:
            min_win = max_win = mean_win = 0
        
        # TTL statistics
        if stats.ttl_values:
            min_ttl = min(stats.ttl_values)
            max_ttl = max(stats.ttl_values)
            mean_ttl = np.mean(stats.ttl_values)
        else:
            min_ttl = max_ttl = mean_ttl = 0
        
        # Forward packet statistics
        if stats.fwd_packet_sizes:
            fwd_min = min(stats.fwd_packet_sizes)
            fwd_max = max(stats.fwd_packet_sizes)
            fwd_mean = np.mean(stats.fwd_packet_sizes)
        else:
            fwd_min = fwd_max = fwd_mean = 0
        
        # Backward packet statistics
        if stats.bwd_packet_sizes:
            bwd_min = min(stats.bwd_packet_sizes)
            bwd_max = max(stats.bwd_packet_sizes)
            bwd_mean = np.mean(stats.bwd_packet_sizes)
        else:
            bwd_min = bwd_max = bwd_mean = 0
        
        # Forward IAT statistics
        if stats.fwd_iat_times:
            fwd_min_iat = min(stats.fwd_iat_times)
            fwd_max_iat = max(stats.fwd_iat_times)
            fwd_mean_iat = np.mean(stats.fwd_iat_times)
        else:
            fwd_min_iat = fwd_max_iat = fwd_mean_iat = 0
        
        # Backward IAT statistics
        if stats.bwd_iat_times:
            bwd_min_iat = min(stats.bwd_iat_times)
            bwd_max_iat = max(stats.bwd_iat_times)
            bwd_mean_iat = np.mean(stats.bwd_iat_times)
        else:
            bwd_min_iat = bwd_max_iat = bwd_mean_iat = 0
        
        # Payload entropy
        payload_entropy = self._calculate_entropy(flow)
        
        # Protocol encoding
        protocol_type = flow.protocol.value
        is_established = 1.0 if flow.state == FlowState.ESTABLISHED else 0.0
        
        # Port features
        port_is_well_known = 1.0 if (flow.dst_port < 1024 or 
                                     flow.src_port < 1024) else 0.0
        
        features = np.array([
            duration,
            stats.packet_count,
            stats.byte_count,
            stats.payload_byte_count,
            stats.fwd_packet_count,
            stats.bwd_packet_count,
            stats.fwd_byte_count,
            stats.bwd_byte_count,
            packets_per_second,
            bytes_per_second,
            fwd_bwd_packet_ratio,
            fwd_bwd_byte_ratio,
            min_pkt, max_pkt, mean_pkt, std_pkt,
            min_iat, max_iat, mean_iat, std_iat,
            stats.syn_count,
            stats.ack_count,
            stats.fin_count,
            stats.rst_count,
            stats.psh_count,
            stats.urg_count,
            min_win, max_win, mean_win,
            min_ttl, max_ttl, mean_ttl,
            fwd_min, fwd_max, fwd_mean,
            bwd_min, bwd_max, bwd_mean,
            fwd_min_iat, fwd_max_iat, fwd_mean_iat,
            bwd_min_iat, bwd_max_iat, bwd_mean_iat,
            payload_entropy,
            protocol_type,
            is_established,
            flow.src_port,
            flow.dst_port,
            port_is_well_known,
        ], dtype=np.float32)
        
        # Cache features
        flow.features = dict(zip(self.FLOW_FEATURE_NAMES, features))
        
        return features
    
    def extract_packet_features(self, packet_info: PacketInfo) -> np.ndarray:
        """Extract features from a single packet"""
        # Packet-level features
        features = np.array([
            packet_info.ip_len,
            packet_info.payload_len,
            packet_info.ttl,
            packet_info.src_port,
            packet_info.dst_port,
            packet_info.protocol.value,
            packet_info.ip_version,
            packet_info.window_size,
            float(packet_info.flags.get('SYN', False)),
            float(packet_info.flags.get('ACK', False)),
            float(packet_info.flags.get('FIN', False)),
            float(packet_info.flags.get('RST', False)),
            float(packet_info.flags.get('PSH', False)),
            float(packet_info.flags.get('URG', False)),
            self._calculate_payload_entropy(packet_info.payload),
        ], dtype=np.float32)
        
        return features
    
    def extract_payload_bytes(self, packet_info: PacketInfo, 
                             max_bytes: int = 1024) -> np.ndarray:
        """Extract raw payload bytes as features"""
        payload = packet_info.payload[:max_bytes]
        
        # Pad or truncate
        if len(payload) < max_bytes:
            payload = payload + b'\x00' * (max_bytes - len(payload))
        
        return np.frombuffer(payload, dtype=np.uint8).astype(np.float32) / 255.0
    
    def _calculate_entropy(self, flow: NetworkFlow) -> float:
        """Calculate entropy of all payloads in flow"""
        if not flow.packets:
            return 0.0
        
        combined_payload = b''.join(p.payload for p in flow.packets if p.payload)
        return self._calculate_payload_entropy(combined_payload)
    
    def _calculate_payload_entropy(self, payload: bytes) -> float:
        """Calculate Shannon entropy of payload"""
        if not payload:
            return 0.0
        
        byte_counts = np.zeros(256, dtype=np.float64)
        for byte in payload:
            byte_counts[byte] += 1
        
        byte_probs = byte_counts[byte_counts > 0] / len(payload)
        entropy = -np.sum(byte_probs * np.log2(byte_probs))
        
        return entropy / 8.0  # Normalize to 0-1


class TrafficNormalizer:
    """Normalize traffic data for ML models"""
    
    def __init__(self):
        self.feature_stats: Dict[str, Dict[str, float]] = {}
        self.fitted = False
    
    def fit(self, features: np.ndarray, feature_names: List[str] = None):
        """Fit normalizer to training data"""
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(features.shape[1])]
        
        for i, name in enumerate(feature_names):
            col = features[:, i]
            self.feature_stats[name] = {
                'mean': float(np.mean(col)),
                'std': float(np.std(col) + 1e-8),
                'min': float(np.min(col)),
                'max': float(np.max(col))
            }
        
        self.fitted = True
    
    def transform(self, features: np.ndarray, 
                 method: str = 'zscore') -> np.ndarray:
        """Transform features using fitted statistics"""
        if not self.fitted:
            raise RuntimeError("Normalizer not fitted")
        
        normalized = np.zeros_like(features, dtype=np.float32)
        
        for i, (name, stats) in enumerate(self.feature_stats.items()):
            if i >= features.shape[1]:
                break
            
            if method == 'zscore':
                normalized[:, i] = (features[:, i] - stats['mean']) / stats['std']
            elif method == 'minmax':
                range_val = stats['max'] - stats['min']
                if range_val > 0:
                    normalized[:, i] = (features[:, i] - stats['min']) / range_val
                else:
                    normalized[:, i] = 0
            else:
                raise ValueError(f"Unknown normalization method: {method}")
        
        return normalized
    
    def fit_transform(self, features: np.ndarray, 
                     feature_names: List[str] = None,
                     method: str = 'zscore') -> np.ndarray:
        """Fit and transform in one step"""
        self.fit(features, feature_names)
        return self.transform(features, method)
    
    def save(self, filepath: str):
        """Save normalizer statistics"""
        import json
        with open(filepath, 'w') as f:
            json.dump(self.feature_stats, f)
    
    def load(self, filepath: str):
        """Load normalizer statistics"""
        import json
        with open(filepath, 'r') as f:
            self.feature_stats = json.load(f)
        self.fitted = True


class TrafficProcessor:
    """Main traffic processor - orchestrates all processing components"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize components
        self.parser = PacketParser()
        self.flow_tracker = FlowTracker(
            flow_timeout=self.config.get('flow_timeout', 120.0),
            max_flows=self.config.get('max_flows', 100000)
        )
        self.feature_extractor = FeatureExtractor()
        self.normalizer = TrafficNormalizer()
        
        # Initialize Deep Packet Inspector
        self.dpi = None
        if DeepPacketInspector:
            try:
                self.dpi = DeepPacketInspector()
                logger.info("DeepPacketInspector integrated into TrafficProcessor")
            except Exception as e:
                logger.error(f"Failed to initialize DeepPacketInspector: {e}")
        
        # Processing queue
        self.packet_queue: Queue = Queue(maxsize=10000)
        self.processed_queue: Queue = Queue(maxsize=10000)
        
        # Callbacks
        self.on_packet_processed: Optional[Callable] = None
        self.on_flow_ready: Optional[Callable] = None
        
        # Processing state
        self.running = False
        self.processing_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            'packets_received': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
            'processing_errors': 0,
            'avg_processing_time': 0.0
        }
        
        # Set up flow callbacks
        self.flow_tracker.on_flow_completed = self._on_flow_completed
        self.flow_tracker.on_flow_expired = self._on_flow_expired
        
        logger.info("TrafficProcessor initialized")
    
    def start(self):
        """Start traffic processing"""
        if self.running:
            logger.warning("TrafficProcessor already running")
            return
        
        self.running = True
        
        # Start processing thread
        self.processing_thread = threading.Thread(
            target=self._processing_loop,
            name="TrafficProcessor"
        )
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="FlowCleanup"
        )
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        logger.info("TrafficProcessor started")
    
    def stop(self):
        """Stop traffic processing"""
        self.running = False
        
        if self.processing_thread:
            self.processing_thread.join(timeout=5.0)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5.0)
        
        logger.info("TrafficProcessor stopped")
    
    def enqueue_packet(self, packet: Any, timestamp: float = None,
                      interface: str = "") -> bool:
        """Add packet to processing queue"""
        self.stats['packets_received'] += 1
        
        try:
            self.packet_queue.put_nowait((packet, timestamp, interface))
            return True
        except:
            self.stats['packets_dropped'] += 1
            return False
    
    def process_packet_sync(self, packet: Any, timestamp: float = None,
                           interface: str = "") -> Optional[Tuple[PacketInfo, NetworkFlow]]:
        """Process a packet synchronously"""
        start_time = time.time()
        
        try:
            # Parse packet
            packet_info = self.parser.parse_packet(packet, timestamp, interface)
            if not packet_info:
                return None
            
            # Update flow
            flow = self.flow_tracker.process_packet(packet_info)
            
            # Extract features if flow has enough packets
            if flow.statistics.packet_count >= 5:
                features = self.feature_extractor.extract_flow_features(flow)
                if self.normalizer.fitted:
                    features = self.normalizer.transform(features.reshape(1, -1))[0]
            
            # Deep Packet Inspection
            if self.dpi:
                try:
                    # Analyze packet
                    analysis = self.dpi.analyze_packet(packet)
                    
                    if not analysis.is_allowed:
                        # Update flow threat score
                        flow.threat_score = max(flow.threat_score, analysis.threat_score)
                        
                        # Add metadata
                        if 'dpi_threats' not in flow.metadata:
                            flow.metadata['dpi_threats'] = []
                        
                        threat_info = {
                            'timestamp': time.time(),
                            'reason': analysis.reason,
                            'score': analysis.threat_score,
                            'details': analysis.metadata
                        }
                        flow.metadata['dpi_threats'].append(threat_info)
                        
                        # Log high severity threats
                        if analysis.threat_score > 0.8:
                            logger.warning(f"DPI Threat Detected: {analysis.reason} (Score: {analysis.threat_score}) - Flow: {flow.flow_id}")
                except Exception as e:
                    logger.debug(f"DPI analysis error: {e}")
            
            # Update stats
            processing_time = time.time() - start_time
            self._update_processing_stats(processing_time)
            
            # Callback
            if self.on_packet_processed:
                self.on_packet_processed(packet_info, flow)
            
            return packet_info, flow
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error processing packet: {e}")
            return None
    
    def _processing_loop(self):
        """Main processing loop"""
        while self.running:
            try:
                packet_data = self.packet_queue.get(timeout=0.1)
                packet, timestamp, interface = packet_data
                
                result = self.process_packet_sync(packet, timestamp, interface)
                
                if result:
                    try:
                        self.processed_queue.put_nowait(result)
                    except:
                        pass
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Processing loop error: {e}")
    
    def _cleanup_loop(self):
        """Periodic flow cleanup"""
        cleanup_interval = self.config.get('cleanup_interval', 30.0)
        
        while self.running:
            try:
                time.sleep(cleanup_interval)
                expired = self.flow_tracker.cleanup_expired()
                
                if expired:
                    logger.debug(f"Cleaned up {len(expired)} expired flows")
                    
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
    
    def _on_flow_completed(self, flow: NetworkFlow):
        """Handle completed flow"""
        # Extract final features
        features = self.feature_extractor.extract_flow_features(flow)
        
        if self.on_flow_ready:
            self.on_flow_ready(flow, features)
    
    def _on_flow_expired(self, flow: NetworkFlow):
        """Handle expired flow"""
        # Extract final features
        features = self.feature_extractor.extract_flow_features(flow)
        
        if self.on_flow_ready:
            self.on_flow_ready(flow, features)
    
    def _update_processing_stats(self, processing_time: float):
        """Update processing statistics"""
        self.stats['packets_processed'] += 1
        
        # Exponential moving average for processing time
        alpha = 0.1
        if self.stats['avg_processing_time'] == 0:
            self.stats['avg_processing_time'] = processing_time
        else:
            self.stats['avg_processing_time'] = (
                alpha * processing_time + 
                (1 - alpha) * self.stats['avg_processing_time']
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            **self.stats,
            'parser_stats': self.parser.stats,
            'flow_stats': self.flow_tracker.stats,
            'queue_size': self.packet_queue.qsize()
        }
    
    def get_flow(self, flow_id: str) -> Optional[NetworkFlow]:
        """Get a specific flow"""
        return self.flow_tracker.get_flow(flow_id)
    
    def get_active_flows(self) -> List[NetworkFlow]:
        """Get all active flows"""
        return self.flow_tracker.get_active_flows()


# Async wrapper for the TrafficProcessor
class AsyncTrafficProcessor:
    """Async wrapper for TrafficProcessor"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.processor = TrafficProcessor(config)
        self._lock = asyncio.Lock()
    
    async def start(self):
        """Start async processor"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.processor.start)
    
    async def stop(self):
        """Stop async processor"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.processor.stop)
    
    async def process_packet(self, packet: Any, timestamp: float = None,
                            interface: str = "") -> Optional[Tuple[PacketInfo, NetworkFlow]]:
        """Process packet asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, 
            self.processor.process_packet_sync,
            packet, timestamp, interface
        )
    
    async def get_processed_packets(self) -> List[Tuple[PacketInfo, NetworkFlow]]:
        """Get all processed packets from queue"""
        results = []
        while True:
            try:
                result = self.processor.processed_queue.get_nowait()
                results.append(result)
            except Empty:
                break
        return results


if __name__ == "__main__":
    # Test the traffic processor
    logging.basicConfig(level=logging.DEBUG)
    
    processor = TrafficProcessor()
    processor.start()
    
    # Simulate some packets
    if SCAPY_AVAILABLE:
        from scapy.all import IP, TCP, Raw
        
        # Create test packets
        for i in range(10):
            pkt = IP(src="192.168.1.100", dst="10.0.0.1") / \
                  TCP(sport=12345, dport=80, flags="S") / \
                  Raw(load=b"GET / HTTP/1.1\r\n")
            
            result = processor.process_packet_sync(pkt)
            if result:
                packet_info, flow = result
                print(f"Processed packet {i}: {packet_info.src_ip}:{packet_info.src_port} -> "
                      f"{packet_info.dst_ip}:{packet_info.dst_port}")
    
    print("\nStatistics:", processor.get_stats())
    
    processor.stop()
