"""IP/port blocking engine."""

from typing import Set
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class BlockingEngine:
    """Manage IP and port blocking."""
    
    def __init__(self):
        """Initialize blocking engine."""
        self.blocked_ips: Set[str] = set()
        self.blocked_ports: Set[int] = set()
    
    def block_ip(self, ip: str) -> bool:
        """Block an IP address."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            logger.warning("Blocked IP", ip=ip)
            return True
        return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            logger.info("Unblocked IP", ip=ip)
            return True
        return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return ip in self.blocked_ips

