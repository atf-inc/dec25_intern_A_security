"""IP/port blocking engine with OS-independent tracker."""

from typing import Set, Optional, Dict, Any
import structlog
from ..config.logging_config import get_logger
from .ip_blocking_tracker import IPBlockingTracker

logger = get_logger(__name__)


class BlockingEngine:
    """
    Manage IP and port blocking using OS-independent tracker.
    Works on both Windows 11 and Kali Linux.
    """
    
    def __init__(self, storage_path: str = "data/blocked_ips.json"):
        """
        Initialize blocking engine.
        
        Args:
            storage_path: Path for persistent storage
        """
        # Use the OS-independent IP blocking tracker
        self.tracker = IPBlockingTracker(storage_path=storage_path)
        self.blocked_ports: Set[int] = set()
        logger.info("BlockingEngine initialized with OS-independent tracker")
    
    def block_ip(self, 
                 ip: str,
                 reason: str = "Security threat detected",
                 duration: Optional[int] = None,
                 threat_level: str = "medium",
                 source: str = "system",
                 metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for permanent)
            threat_level: Threat level (low, medium, high, critical)
            source: Source of the block
            metadata: Additional metadata
        
        Returns:
            True if blocked successfully
        """
        return self.tracker.block_ip(
            ip=ip,
            reason=reason,
            duration=duration,
            threat_level=threat_level,
            source=source,
            metadata=metadata
        )
    
    def unblock_ip(self, ip: str, manual: bool = True) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip: IP address to unblock
            manual: True if manually unblocked
        
        Returns:
            True if unblocked successfully
        """
        return self.tracker.unblock_ip(ip=ip, manual=manual)
    
    def is_blocked(self, ip: str) -> bool:
        """
        Check if IP is blocked.
        
        Args:
            ip: IP address to check
        
        Returns:
            True if blocked and active
        """
        return self.tracker.is_blocked(ip)
    
    def get_block_info(self, ip: str):
        """Get block information for an IP"""
        return self.tracker.get_block_info(ip)
    
    def get_all_blocked_ips(self, include_expired: bool = False):
        """Get all blocked IPs"""
        return self.tracker.get_all_blocked_ips(include_expired=include_expired)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get blocking statistics"""
        return self.tracker.get_statistics()
    
    def block_port(self, port: int) -> bool:
        """Block a port (in-memory only for now)."""
        if port not in self.blocked_ports:
            self.blocked_ports.add(port)
            logger.warning(f"Blocked port: {port}")
            return True
        return False
    
    def unblock_port(self, port: int) -> bool:
        """Unblock a port."""
        if port in self.blocked_ports:
            self.blocked_ports.remove(port)
            logger.info(f"Unblocked port: {port}")
            return True
        return False
    
    def is_port_blocked(self, port: int) -> bool:
        """Check if port is blocked."""
        return port in self.blocked_ports
    
    def cleanup_expired(self) -> int:
        """Cleanup expired blocks"""
        return self.tracker.cleanup_expired()

