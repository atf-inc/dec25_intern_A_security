"""
Trap Tracker Module

Tracks which IP addresses have been flagged as attackers and should be
permanently routed to the honeypot for all subsequent requests.

Once trapped, an attacker stays trapped until:
1. The trap expires (default 30 minutes)
2. Manually cleared via debug endpoint
"""

import time
import logging
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger("trap_tracker")

# Default trap duration: 30 minutes
DEFAULT_TRAP_DURATION_SECONDS = 30 * 60


class TrapTracker:
    """
    In-memory tracker for trapped attacker sessions.
    """

    def __init__(self, trap_duration: int = DEFAULT_TRAP_DURATION_SECONDS):
        self._trapped: Dict[str, Dict[str, Any]] = {}
        self.trap_duration = trap_duration

    def trap_session(self, ip: str, reason: str, attack_payload: str = "") -> None:
        """
        Add an IP to the trap list.
        
        Args:
            ip: The IP address to trap
            reason: Why they were trapped (e.g., "SQL Injection detected")
            attack_payload: The malicious payload that triggered the trap
        """
        self._trapped[ip] = {
            "trapped_at": time.time(),
            "trapped_at_human": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason,
            "attack_payload": attack_payload[:200],  # Truncate for safety
            "request_count": 0  # Track how many requests while trapped
        }
        logger.warning(f"[TRAPPED] IP {ip} trapped: {reason}")

    def is_trapped(self, ip: str) -> bool:
        """
        Check if an IP is currently trapped.
        Also handles auto-expiration of old traps.
        
        Returns:
            True if IP is trapped and trap hasn't expired
        """
        if ip not in self._trapped:
            return False

        trap_info = self._trapped[ip]
        elapsed = time.time() - trap_info["trapped_at"]

        # Check if trap has expired
        if elapsed > self.trap_duration:
            logger.info(f"[TRAP EXPIRED] IP {ip} trap expired after {elapsed:.0f}s")
            del self._trapped[ip]
            return False

        # Increment request count
        trap_info["request_count"] += 1
        return True

    def get_trap_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed trap information for an IP.
        
        Returns:
            Trap info dict or None if not trapped
        """
        if not self.is_trapped(ip):
            return None

        info = self._trapped[ip].copy()
        info["elapsed_seconds"] = int(time.time() - info["trapped_at"])
        info["remaining_seconds"] = max(0, self.trap_duration - info["elapsed_seconds"])
        return info

    def clear_trap(self, ip: str) -> bool:
        """
        Remove an IP from the trap list.
        
        Returns:
            True if trap was cleared, False if IP wasn't trapped
        """
        if ip in self._trapped:
            del self._trapped[ip]
            logger.info(f"[TRAP CLEARED] IP {ip} manually cleared")
            return True
        return False

    def clear_all_traps(self) -> int:
        """
        Clear all trapped IPs.
        
        Returns:
            Number of traps cleared
        """
        count = len(self._trapped)
        self._trapped.clear()
        logger.info(f"[ALL TRAPS CLEARED] Cleared {count} traps")
        return count

    def get_all_traps(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all currently trapped IPs and their info.
        Also cleans up expired traps.
        """
        # Clean up expired traps
        current_time = time.time()
        expired = [
            ip for ip, info in self._trapped.items()
            if current_time - info["trapped_at"] > self.trap_duration
        ]
        for ip in expired:
            del self._trapped[ip]

        # Return copy with elapsed times
        result = {}
        for ip, info in self._trapped.items():
            result[ip] = info.copy()
            result[ip]["elapsed_seconds"] = int(current_time - info["trapped_at"])
        return result


# Singleton instance
trap_tracker = TrapTracker()

