"""IP/port blocking engine with persistence."""

from typing import Set
import json
import os
import logging

try:
    from config.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class BlockingEngine:
    """Manage IP and port blocking with persistence."""
    
    def __init__(self, persistence_file: str = "data/blocked_ips.json"):
        """Initialize blocking engine."""
        self.blocked_ips: Set[str] = set()
        self.blocked_ports: Set[int] = set()
        self.persistence_file = persistence_file
        self._ensure_data_dir()
        self._load_blocked_ips()
    
    def _ensure_data_dir(self):
        """Ensure the data directory exists."""
        directory = os.path.dirname(self.persistence_file)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

    def _load_blocked_ips(self):
        """Load blocked IPs from disk."""
        if os.path.exists(self.persistence_file):
            try:
                with open(self.persistence_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('ips', []))
                    logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from {self.persistence_file}")
            except Exception as e:
                logger.error(f"Failed to load blocked IPs: {e}")

    def _save_blocked_ips(self):
        """Save blocked IPs to disk."""
        try:
            with open(self.persistence_file, 'w') as f:
                json.dump({'ips': list(self.blocked_ips)}, f)
        except Exception as e:
            logger.error(f"Failed to save blocked IPs: {e}")

    def block_ip(self, ip: str) -> bool:
        """Block an IP address."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            logger.warning("Blocked IP", extra={"ip": ip})
            self._save_blocked_ips()
            return True
        return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            logger.info("Unblocked IP", extra={"ip": ip})
            self._save_blocked_ips()
            return True
        return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return ip in self.blocked_ips
