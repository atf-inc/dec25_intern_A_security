"""IP and domain reputation engine."""

from typing import Dict, Any, Optional
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class ReputationEngine:
    """IP and domain reputation checking."""
    
    def __init__(self):
        """Initialize reputation engine."""
        self.reputation_cache: Dict[str, Dict[str, Any]] = {}
        self.blacklists: Dict[str, set] = {
            "ips": set(),
            "domains": set(),
        }
    
    async def initialize(self) -> None:
        """Initialize reputation engine."""
        logger.info("Initializing reputation engine")
        await self._load_blacklists()
    
    async def _load_blacklists(self) -> None:
        """Load IP and domain blacklists."""
        # Would load from threat intelligence feeds
        # Example blacklisted IPs (for demonstration)
        self.blacklists["ips"].update([
            "192.0.2.1",
            "203.0.113.1",
        ])
    
    async def check_reputation(
        self, ip: Optional[str] = None, domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check reputation of IP or domain.
        
        Returns:
            Dict with reputation_score, is_malicious, and details
        """
        if ip:
            return await self._check_ip_reputation(ip)
        elif domain:
            return await self._check_domain_reputation(domain)
        
        return {"reputation_score": 0.5, "is_malicious": False}
    
    async def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation."""
        # Check cache
        if ip in self.reputation_cache:
            return self.reputation_cache[ip]
        
        # Check blacklist
        is_malicious = ip in self.blacklists["ips"]
        
        # In real implementation, would query threat intelligence APIs
        reputation_score = 0.0 if is_malicious else 0.5
        
        result = {
            "reputation_score": reputation_score,
            "is_malicious": is_malicious,
            "source": "blacklist" if is_malicious else "unknown",
        }
        
        # Cache result
        self.reputation_cache[ip] = result
        
        return result
    
    async def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation."""
        # Similar to IP reputation checking
        is_malicious = domain in self.blacklists["domains"]
        
        return {
            "reputation_score": 0.0 if is_malicious else 0.5,
            "is_malicious": is_malicious,
            "source": "blacklist" if is_malicious else "unknown",
        }

