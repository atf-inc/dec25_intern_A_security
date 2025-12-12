"""
Packet Capture Module
High-performance packet capture using Scapy and raw sockets
"""

import asyncio
import logging
from typing import List, Optional, Dict
from scapy.all import sniff, AsyncSniffer, IP, TCP, UDP, ICMP, Raw
from collections import deque
import time

logger = logging.getLogger(__name__)


class PacketCapture:
    """High-performance packet capture interface"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.interface = config.get('interface', 'eth0')
        self.filter_bpf = config.get('filter', '')
        self.snaplen = config.get('snaplen', 65535)
        self.promisc = config.get('promisc', True)
        
        # Ring buffer for captured packets
        self.buffer_size = config.get('buffer_size', 10000)
        self.packet_buffer = deque(maxlen=self.buffer_size)
        
        # Sniffer instance
        self.sniffer: Optional[AsyncSniffer] = None
        self.running = False
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'packets_dropped': 0,
            'bytes_captured': 0
        }
        
        logger.info(f"PacketCapture initialized on interface {self.interface}")
    
    async def start(self):
        """Start packet capture"""
        if self.running:
            logger.warning("Packet capture already running")
            return
        
        logger.info(f"Starting packet capture on {self.interface}")
        self.running = True
        
        # Create async sniffer
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_handler,
            filter=self.filter_bpf,
            store=False,
            promisc=self.promisc
        )
        
        # Start sniffing
        self.sniffer.start()
        
        logger.info("Packet capture started")
    
    async def stop(self):
        """Stop packet capture"""
        if not self.running:
            return
        
        logger.info("Stopping packet capture")
        self.running = False
        
        if self.sniffer:
            self.sniffer.stop()
        
        logger.info(f"Packet capture stopped. Captured {self.stats['packets_captured']} packets")
    
    def _packet_handler(self, packet):
        """Handle captured packet"""
        try:
            # Parse packet
            parsed = self._parse_packet(packet)
            
            if parsed:
                # Add to buffer
                if len(self.packet_buffer) >= self.buffer_size:
                    self.stats['packets_dropped'] += 1
                
                self.packet_buffer.append(parsed)
                self.stats['packets_captured'] += 1
                self.stats['bytes_captured'] += parsed.get('length', 0)
                
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
    
    def _parse_packet(self, packet) -> Optional[Dict]:
        """Parse packet into dictionary format"""
        try:
            parsed = {
                'timestamp': time.time(),
                'length': len(packet)
            }
            
            # IP layer
            if IP in packet:
                ip = packet[IP]
                parsed.update({
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'ttl': ip.ttl,
                    'ip_id': ip.id,
                    'ip_flags': ip.flags,
                    'protocol': ip.proto
                })
            
            # TCP layer
            if TCP in packet:
                tcp = packet[TCP]
                parsed.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'tcp_flags': tcp.flags,
                    'tcp_seq': tcp.seq,
                    'tcp_ack': tcp.ack,
                    'tcp_window': tcp.window,
                    'protocol_name': 'TCP'
                })
            
            # UDP layer
            elif UDP in packet:
                udp = packet[UDP]
                parsed.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'protocol_name': 'UDP'
                })
            
            # ICMP layer
            elif ICMP in packet:
                icmp = packet[ICMP]
                parsed.update({
                    'icmp_type': icmp.type,
                    'icmp_code': icmp.code,
                    'protocol_name': 'ICMP'
                })
            
            # Payload
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                parsed['payload'] = payload
                parsed['payload_size'] = len(payload)
                parsed['payload_hex'] = payload[:100].hex()  # First 100 bytes
            else:
                parsed['payload_size'] = 0
            
            # Raw bytes
            parsed['raw_packet'] = bytes(packet)
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None
    
    async def capture_batch(self, batch_size: int = 100, timeout: float = 0.1) -> List[Dict]:
        """Capture a batch of packets"""
        packets = []
        start_time = time.time()
        
        while len(packets) < batch_size:
            if not self.running:
                break
            
            # Check timeout
            if time.time() - start_time > timeout:
                break
            
            # Get packets from buffer
            try:
                if self.packet_buffer:
                    packets.append(self.packet_buffer.popleft())
                else:
                    # Small sleep if buffer is empty
                    await asyncio.sleep(0.001)
            except IndexError:
                break
        
        return packets
    
    async def capture_single(self, timeout: float = 1.0) -> Optional[Dict]:
        """Capture a single packet"""
        start_time = time.time()
        
        while self.running:
            if time.time() - start_time > timeout:
                return None
            
            if self.packet_buffer:
                return self.packet_buffer.popleft()
            
            await asyncio.sleep(0.001)
        
        return None
    
    def get_buffer_status(self) -> Dict:
        """Get buffer status"""
        return {
            'buffer_size': len(self.packet_buffer),
            'buffer_capacity': self.buffer_size,
            'buffer_utilization': len(self.packet_buffer) / self.buffer_size
        }
    
    def get_statistics(self) -> Dict:
        """Get capture statistics"""
        return {
            **self.stats,
            'buffer_status': self.get_buffer_status(),
            'drop_rate': (
                self.stats['packets_dropped'] / self.stats['packets_captured']
                if self.stats['packets_captured'] > 0 else 0
            )
        }
    
    def set_filter(self, bpf_filter: str):
        """Update BPF filter"""
        self.filter_bpf = bpf_filter
        logger.info(f"Updated BPF filter: {bpf_filter}")
        
        # Restart sniffer with new filter if running
        if self.running and self.sniffer:
            asyncio.create_task(self._restart_with_filter())
    
    async def _restart_with_filter(self):
        """Restart sniffer with new filter"""
        await self.stop()
        await asyncio.sleep(0.5)
        await self.start()