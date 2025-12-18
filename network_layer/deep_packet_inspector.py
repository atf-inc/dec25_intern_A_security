#!/usr/bin/env python3
"""
OS-Independent Deep Packet Inspector
Uses scapy and dpkt for deep packet inspection
Works on both Windows 11 and Kali Linux
"""

import logging
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
import numpy as np

logger = logging.getLogger(__name__)

# Try to import scapy
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, HTTP, Raw, Ether, ARP, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
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

# Try to import dpkt
try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False
    dpkt = None


@dataclass
class PacketAnalysis:
    """Results of deep packet inspection"""
    protocol: str
    application_protocol: Optional[str] = None
    payload_signatures: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    encryption_detected: bool = False
    compression_detected: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    threat_score: float = 0.0


class DeepPacketInspector:
    """
    OS-independent deep packet inspector using Python libraries.
    Works on both Windows 11 and Kali Linux.
    """
    
    # Common attack patterns in payloads
    SQL_INJECTION_PATTERNS = [
        b"' OR '1'='1",
        b"' OR 1=1--",
        b"UNION SELECT",
        b"; DROP TABLE",
        b"; DELETE FROM",
        b"EXEC(",
        b"xp_cmdshell",
        b"LOAD_FILE",
    ]
    
    XSS_PATTERNS = [
        b"<script>",
        b"javascript:",
        b"onerror=",
        b"onload=",
        b"eval(",
        b"document.cookie",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        b"; /bin/sh",
        b"; cat /etc/passwd",
        b"| nc ",
        b"&& id",
        b"`whoami`",
    ]
    
    def __init__(self):
        """Initialize deep packet inspector"""
        self.enabled = SCAPY_AVAILABLE or DPKT_AVAILABLE
        if not self.enabled:
            logger.warning("Neither scapy nor dpkt available. Deep packet inspection disabled.")
        else:
            logger.info("Deep Packet Inspector initialized (OS-independent)")
        
        self.stats = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'by_protocol': {},
        }
    
    def analyze_packet(self, packet: Any, packet_info: Optional[Dict[str, Any]] = None) -> PacketAnalysis:
        """
        Perform deep packet inspection on a packet.
        
        Args:
            packet: Packet object (scapy packet, dpkt packet, or raw bytes)
            packet_info: Optional pre-parsed packet information
        
        Returns:
            PacketAnalysis object with inspection results
        """
        if not self.enabled:
            return PacketAnalysis(protocol="unknown")
        
        self.stats['packets_analyzed'] += 1
        
        try:
            # Try scapy first
            if SCAPY_AVAILABLE and hasattr(packet, 'summary'):
                return self._analyze_scapy_packet(packet, packet_info)
            
            # Try dpkt
            elif DPKT_AVAILABLE and isinstance(packet, (bytes, bytearray)):
                return self._analyze_dpkt_packet(packet, packet_info)
            
            # Fallback to basic analysis
            elif packet_info:
                return self._analyze_from_info(packet_info)
            
            else:
                return PacketAnalysis(protocol="unknown")
                
        except Exception as e:
            logger.debug(f"Error analyzing packet: {e}")
            return PacketAnalysis(protocol="unknown")
    
    def _analyze_scapy_packet(self, packet: Any, packet_info: Optional[Dict[str, Any]]) -> PacketAnalysis:
        """Analyze packet using scapy"""
        protocol = "unknown"
        app_protocol = None
        payload = b''
        suspicious_patterns = []
        payload_signatures = []
        
        # Identify protocol
        if IP in packet:
            protocol = "IPv4"
            ip_layer = packet[IP]
            
            # Check transport layer
            if TCP in packet:
                protocol = "TCP"
                tcp_layer = packet[TCP]
                dst_port = tcp_layer.dport
                app_protocol = self._identify_application_protocol(dst_port, tcp_layer)
                
                # Extract payload
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    
            elif UDP in packet:
                protocol = "UDP"
                udp_layer = packet[UDP]
                dst_port = udp_layer.dport
                app_protocol = self._identify_application_protocol(dst_port, udp_layer)
                
                # Extract payload
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    
            elif ICMP in packet:
                protocol = "ICMP"
                
        elif IPv6 in packet:
            protocol = "IPv6"
            # Similar analysis for IPv6
            if TCP in packet:
                protocol = "TCP"
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
        
        # Analyze payload for threats
        if payload:
            suspicious_patterns = self._detect_suspicious_patterns(payload)
            payload_signatures = self._extract_signatures(payload)
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(suspicious_patterns, payload_signatures)
        
        if threat_score > 0:
            self.stats['threats_detected'] += 1
        
        # Update protocol stats
        if protocol not in self.stats['by_protocol']:
            self.stats['by_protocol'][protocol] = 0
        self.stats['by_protocol'][protocol] += 1
        
        return PacketAnalysis(
            protocol=protocol,
            application_protocol=app_protocol,
            payload_signatures=payload_signatures,
            suspicious_patterns=suspicious_patterns,
            metadata={
                'payload_length': len(payload),
                'has_encryption': self._detect_encryption(payload),
                'has_compression': self._detect_compression(payload),
            },
            threat_score=threat_score
        )
    
    def _analyze_dpkt_packet(self, packet: bytes, packet_info: Optional[Dict[str, Any]]) -> PacketAnalysis:
        """Analyze packet using dpkt"""
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                protocol = "IPv4"
                
                if isinstance(ip.data, dpkt.tcp.TCP):
                    protocol = "TCP"
                    tcp = ip.data
                    app_protocol = self._identify_application_protocol(tcp.dport, None)
                    payload = tcp.data
                    
                elif isinstance(ip.data, dpkt.udp.UDP):
                    protocol = "UDP"
                    udp = ip.data
                    app_protocol = self._identify_application_protocol(udp.dport, None)
                    payload = udp.data
                else:
                    payload = b''
            else:
                protocol = "unknown"
                payload = b''
            
            # Analyze payload
            suspicious_patterns = self._detect_suspicious_patterns(payload) if payload else []
            payload_signatures = self._extract_signatures(payload) if payload else []
            threat_score = self._calculate_threat_score(suspicious_patterns, payload_signatures)
            
            return PacketAnalysis(
                protocol=protocol,
                application_protocol=app_protocol,
                payload_signatures=payload_signatures,
                suspicious_patterns=suspicious_patterns,
                metadata={'payload_length': len(payload)},
                threat_score=threat_score
            )
            
        except Exception as e:
            logger.debug(f"Error in dpkt analysis: {e}")
            return PacketAnalysis(protocol="unknown")
    
    def _analyze_from_info(self, packet_info: Dict[str, Any]) -> PacketAnalysis:
        """Basic analysis from packet info dictionary"""
        protocol = packet_info.get('protocol', 'unknown')
        payload = packet_info.get('payload', b'')
        
        suspicious_patterns = self._detect_suspicious_patterns(payload) if payload else []
        payload_signatures = self._extract_signatures(payload) if payload else []
        threat_score = self._calculate_threat_score(suspicious_patterns, payload_signatures)
        
        return PacketAnalysis(
            protocol=protocol,
            payload_signatures=payload_signatures,
            suspicious_patterns=suspicious_patterns,
            threat_score=threat_score
        )
    
    def _identify_application_protocol(self, port: int, layer: Any) -> Optional[str]:
        """Identify application layer protocol from port"""
        port_protocols = {
            20: "FTP",
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
        }
        
        if port in port_protocols:
            return port_protocols[port]
        
        # Try to detect HTTP
        if layer and hasattr(layer, 'load'):
            try:
                payload = bytes(layer.load)
                if payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HTTP'):
                    return "HTTP"
            except:
                pass
        
        return None
    
    def _detect_suspicious_patterns(self, payload: bytes) -> List[str]:
        """Detect suspicious patterns in payload"""
        patterns = []
        payload_lower = payload.lower()
        
        # SQL Injection
        for pattern in self.SQL_INJECTION_PATTERNS:
            if pattern.lower() in payload_lower:
                patterns.append(f"SQL_INJECTION:{pattern.decode('utf-8', errors='ignore')[:20]}")
        
        # XSS
        for pattern in self.XSS_PATTERNS:
            if pattern.lower() in payload_lower:
                patterns.append(f"XSS:{pattern.decode('utf-8', errors='ignore')[:20]}")
        
        # Command Injection
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if pattern in payload:
                patterns.append(f"COMMAND_INJECTION:{pattern.decode('utf-8', errors='ignore')[:20]}")
        
        return patterns
    
    def _extract_signatures(self, payload: bytes) -> List[str]:
        """Extract signatures from payload"""
        signatures = []
        
        # Check for common file signatures
        if payload.startswith(b'%PDF'):
            signatures.append("PDF")
        elif payload.startswith(b'PK\x03\x04'):
            signatures.append("ZIP")
        elif payload.startswith(b'\x89PNG'):
            signatures.append("PNG")
        elif payload.startswith(b'GIF89a') or payload.startswith(b'GIF87a'):
            signatures.append("GIF")
        elif payload.startswith(b'\xff\xd8\xff'):
            signatures.append("JPEG")
        
        return signatures
    
    def _detect_encryption(self, payload: bytes) -> bool:
        """Detect if payload appears encrypted"""
        if len(payload) < 16:
            return False
        
        # High entropy suggests encryption
        entropy = self._calculate_entropy(payload[:256])  # Sample first 256 bytes
        return entropy > 7.0  # High entropy threshold
    
    def _detect_compression(self, payload: bytes) -> bool:
        """Detect if payload appears compressed"""
        # Check for compression signatures
        compression_signatures = [
            b'\x1f\x8b',  # gzip
            b'BZ',        # bzip2
            b'\x78\x01',  # zlib
            b'\x78\x9c',  # zlib
        ]
        
        for sig in compression_signatures:
            if payload.startswith(sig):
                return True
        
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = np.zeros(256, dtype=np.float64)
        for byte in data:
            byte_counts[byte] += 1
        
        byte_probs = byte_counts[byte_counts > 0] / len(data)
        entropy = -np.sum(byte_probs * np.log2(byte_probs))
        
        return entropy
    
    def _calculate_threat_score(self, suspicious_patterns: List[str], signatures: List[str]) -> float:
        """Calculate threat score based on detected patterns"""
        score = 0.0
        
        # SQL Injection patterns
        sql_count = sum(1 for p in suspicious_patterns if 'SQL_INJECTION' in p)
        score += sql_count * 0.8
        
        # XSS patterns
        xss_count = sum(1 for p in suspicious_patterns if 'XSS' in p)
        score += xss_count * 0.7
        
        # Command injection
        cmd_count = sum(1 for p in suspicious_patterns if 'COMMAND_INJECTION' in p)
        score += cmd_count * 0.9
        
        # Normalize to 0-1
        return min(1.0, score / 3.0)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get inspection statistics"""
        return {
            **self.stats,
            'enabled': self.enabled,
            'scapy_available': SCAPY_AVAILABLE,
            'dpkt_available': DPKT_AVAILABLE,
        }

