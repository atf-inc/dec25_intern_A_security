"""Rate limiting engine."""

from typing import Dict, Any
from collections import defaultdict
import time
try:
    from config.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiting for IPs and connections."""
    
    def __init__(self, default_limit: int = 100):
        """Initialize rate limiter."""
        self.rate_limits: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.default_limit = default_limit  # packets per second
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit."""
        now = time.time()
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = {
                "count": 0,
                "window_start": now,
            }
        
        limit_info = self.rate_limits[ip]
        
        # Reset window if expired
        if now - limit_info["window_start"] > 1.0:
            limit_info["count"] = 0
            limit_info["window_start"] = now
        
        limit_info["count"] += 1
        
        # Check limit
        if limit_info["count"] > self.default_limit:
            if limit_info["count"] % 50 == 0: # Log only every 50th excess packet to avoid spam
                logger.warning(f"Rate limit exceeded for {ip}: {limit_info['count']} > {self.default_limit}")
            return False
        
        return True
