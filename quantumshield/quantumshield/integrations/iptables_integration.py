"""IPTables integration for firewall rules."""

import subprocess
from typing import Dict, Any, Optional, List
import structlog
from .base_integration import BaseIntegration
from ...config.logging_config import get_logger

logger = get_logger(__name__)


class IPTablesIntegration(BaseIntegration):
    """Integration with IPTables for firewall rules."""
    
    def __init__(self):
        """Initialize IPTables integration."""
        super().__init__(tool_path="/sbin/iptables")
        self.blocked_ips: set = set()
    
    async def initialize(self) -> None:
        """Initialize IPTables integration."""
        logger.info("Initializing IPTables integration")
        self.enabled = True
    
    async def start(self) -> None:
        """Start IPTables integration."""
        logger.info("Starting IPTables integration")
        self.enabled = True
    
    async def stop(self) -> None:
        """Stop IPTables integration."""
        logger.info("Stopping IPTables integration")
        self.enabled = False
    
    async def block_ip(self, ip: str, chain: str = "INPUT") -> bool:
        """Block an IP address using iptables."""
        if ip in self.blocked_ips:
            return True
        
        try:
            # Add iptables rule to block IP
            cmd = ["iptables", "-A", chain, "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.blocked_ips.add(ip)
            logger.info("Blocked IP via iptables", ip=ip)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to block IP", ip=ip, error=str(e))
            return False
    
    async def unblock_ip(self, ip: str, chain: str = "INPUT") -> bool:
        """Unblock an IP address."""
        if ip not in self.blocked_ips:
            return True
        
        try:
            cmd = ["iptables", "-D", chain, "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.blocked_ips.discard(ip)
            logger.info("Unblocked IP via iptables", ip=ip)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to unblock IP", ip=ip, error=str(e))
            return False
    
    async def analyze(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if IP is blocked."""
        src_ip = packet.get("src_ip")
        if src_ip and src_ip in self.blocked_ips:
            return {
                "blocked": True,
                "reason": "IP is in blocklist",
            }
        return None

