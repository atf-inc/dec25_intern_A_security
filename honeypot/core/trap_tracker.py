"""
Trap Tracker Module

Tracks which IP addresses have been flagged as attackers and should be
permanently routed to the honeypot for all subsequent requests.

Once trapped, an attacker stays trapped until:
1. The trap expires (default 30 minutes)
2. Manually cleared via debug endpoint

Now with MongoDB persistence for analytics and history.
"""

import time
import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from core.database import db

logger = logging.getLogger("trap_tracker")

# Default trap duration: 30 minutes
DEFAULT_TRAP_DURATION_SECONDS = 30 * 60


class TrapTracker:
    """
    Tracker for trapped attacker sessions with MongoDB persistence.
    Uses in-memory cache for fast lookups, persists to DB for analytics.
    """

    def __init__(self, trap_duration: int = DEFAULT_TRAP_DURATION_SECONDS):
        self._trapped: Dict[str, Dict[str, Any]] = {}
        self._malicious_counters: Dict[str, int] = {}  # Track MALICIOUS attempts per IP
        self._permanently_blocked: Dict[str, Dict[str, Any]] = {}  # Permanently blocked IPs
        self.trap_duration = trap_duration
        self.collection_name = "traps"
        self.blocks_collection_name = "permanent_blocks"
        self.malicious_threshold = 5  # Block after 5 MALICIOUS attempts

    def _get_collection(self):
        """Get the traps collection from MongoDB."""
        return db.get_collection(self.collection_name)

    def trap_session(self, ip: str, reason: str, attack_payload: str = "") -> None:
        """
        Add an IP to the trap list.
        
        Args:
            ip: The IP address to trap
            reason: Why they were trapped (e.g., "SQL Injection detected")
            attack_payload: The malicious payload that triggered the trap
        """
        trap_data = {
            "trapped_at": time.time(),
            "trapped_at_human": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "trapped_at_utc": datetime.now(timezone.utc),
            "reason": reason,
            "attack_payload": attack_payload[:500],  # Truncate for safety
            "request_count": 0,  # Track how many requests while trapped
            "active": True
        }
        self._trapped[ip] = trap_data
        logger.warning(f"[TRAPPED] IP {ip} trapped: {reason}")
        
        # Persist to MongoDB in background
        asyncio.create_task(self._persist_trap(ip, trap_data))

    async def _persist_trap(self, ip: str, trap_data: Dict[str, Any]) -> None:
        """Persist trap data to MongoDB."""
        try:
            collection = self._get_collection()
            await collection.update_one(
                {"ip": ip, "active": True},
                {
                    "$set": {
                        "ip": ip,
                        "trapped_at": trap_data["trapped_at_utc"],
                        "reason": trap_data["reason"],
                        "attack_payload": trap_data["attack_payload"],
                        "request_count": trap_data["request_count"],
                        "active": True,
                        "updated_at": datetime.now(timezone.utc)
                    }
                },
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to persist trap for {ip}: {e}")

    async def _update_request_count(self, ip: str, count: int) -> None:
        """Update request count in MongoDB."""
        try:
            collection = self._get_collection()
            await collection.update_one(
                {"ip": ip, "active": True},
                {"$set": {"request_count": count, "updated_at": datetime.now(timezone.utc)}}
            )
        except Exception as e:
            logger.error(f"Failed to update request count for {ip}: {e}")

    async def _release_trap(self, ip: str, reason: str = "expired") -> None:
        """Mark trap as released in MongoDB."""
        try:
            collection = self._get_collection()
            trap_info = self._trapped.get(ip, {})
            await collection.update_one(
                {"ip": ip, "active": True},
                {
                    "$set": {
                        "active": False,
                        "released_at": datetime.now(timezone.utc),
                        "release_reason": reason,
                        "final_request_count": trap_info.get("request_count", 0)
                    }
                }
            )
        except Exception as e:
            logger.error(f"Failed to release trap for {ip}: {e}")

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
            asyncio.create_task(self._release_trap(ip, "expired"))
            del self._trapped[ip]
            return False

        # Increment request count
        trap_info["request_count"] += 1
        # Update in MongoDB periodically (every 5 requests to reduce DB load)
        if trap_info["request_count"] % 5 == 0:
            asyncio.create_task(self._update_request_count(ip, trap_info["request_count"]))
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
            asyncio.create_task(self._release_trap(ip, "manual_clear"))
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
        for ip in list(self._trapped.keys()):
            asyncio.create_task(self._release_trap(ip, "bulk_clear"))
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
            asyncio.create_task(self._release_trap(ip, "expired"))
            del self._trapped[ip]

        # Return copy with elapsed times
        result = {}
        for ip, info in self._trapped.items():
            result[ip] = info.copy()
            result[ip]["elapsed_seconds"] = int(current_time - info["trapped_at"])
        return result

    async def get_trap_history(self, limit: int = 50) -> list:
        """
        Get trap history from MongoDB for analytics.
        
        Returns:
            List of trap records
        """
        try:
            collection = self._get_collection()
            traps = await collection.find().sort("trapped_at", -1).limit(limit).to_list(length=limit)
            for trap in traps:
                trap["_id"] = str(trap["_id"])
            return traps
        except Exception as e:
            logger.error(f"Failed to get trap history: {e}")
            return []

    async def get_active_traps_from_db(self) -> list:
        """
        Get currently active traps from MongoDB.
        Useful for restoring state after restart.
        """
        try:
            collection = self._get_collection()
            traps = await collection.find({"active": True}).to_list(length=None)
            for trap in traps:
                trap["_id"] = str(trap["_id"])
            return traps
        except Exception as e:
            logger.error(f"Failed to get active traps: {e}")
            return []
    
    # ========================================================================
    # COUNTER-BASED PERMANENT BLOCKING
    # ========================================================================
    
    def increment_malicious_counter(self, ip: str) -> int:
        """
        Increment the MALICIOUS attempt counter for an IP.
        
        Returns:
            Current count after increment
        """
        self._malicious_counters[ip] = self._malicious_counters.get(ip, 0) + 1
        count = self._malicious_counters[ip]
        logger.info(f"[MALICIOUS COUNTER] IP {ip} - Attempt #{count}/{self.malicious_threshold}")
        
        # Check if threshold reached
        if count >= self.malicious_threshold:
            asyncio.create_task(self._permanently_block_ip(ip))
        
        return count
    
    async def _permanently_block_ip(self, ip: str) -> None:
        """Permanently block an IP after reaching malicious threshold."""
        if ip in self._permanently_blocked:
            return  # Already blocked
        
        block_data = {
            "blocked_at": time.time(),
            "blocked_at_human": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "blocked_at_utc": datetime.now(timezone.utc),
            "reason": f"Exceeded malicious threshold ({self.malicious_threshold} attempts)",
            "malicious_count": self._malicious_counters.get(ip, 0)
        }
        self._permanently_blocked[ip] = block_data
        logger.error(f"[PERMANENTLY BLOCKED] IP {ip} - {self.malicious_threshold} MALICIOUS attempts")
        
        # Persist to MongoDB
        try:
            collection = db.get_collection(self.blocks_collection_name)
            await collection.update_one(
                {"ip": ip},
                {
                    "$set": {
                        "ip": ip,
                        "blocked_at": block_data["blocked_at_utc"],
                        "reason": block_data["reason"],
                        "malicious_count": block_data["malicious_count"],
                        "active": True
                    }
                },
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to persist permanent block for {ip}: {e}")
    
    def is_permanently_blocked(self, ip: str) -> bool:
        """Check if an IP is permanently blocked."""
        return ip in self._permanently_blocked
    
    def get_block_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get permanent block information for an IP."""
        if ip not in self._permanently_blocked:
            return None
        
        info = self._permanently_blocked[ip].copy()
        info["elapsed_seconds"] = int(time.time() - info["blocked_at"])
        info["malicious_count"] = self._malicious_counters.get(ip, 0)
        return info
    
    def get_malicious_count(self, ip: str) -> int:
        """Get the current malicious attempt count for an IP."""
        return self._malicious_counters.get(ip, 0)
    
    async def unblock_ip(self, ip: str) -> bool:
        """
        Remove an IP from the permanent block list.
        
        Returns:
            True if IP was unblocked, False if not blocked
        """
        if ip not in self._permanently_blocked:
            return False
        
        # Remove from memory
        del self._permanently_blocked[ip]
        self._malicious_counters[ip] = 0  # Reset counter
        logger.info(f"[UNBLOCKED] IP {ip} removed from permanent block list")
        
        # Update MongoDB
        try:
            collection = db.get_collection(self.blocks_collection_name)
            await collection.update_one(
                {"ip": ip},
                {
                    "$set": {
                        "active": False,
                        "unblocked_at": datetime.now(timezone.utc)
                    }
                }
            )
        except Exception as e:
            logger.error(f"Failed to update unblock status for {ip}: {e}")
        
        return True
    
    def get_all_blocked(self) -> Dict[str, Dict[str, Any]]:
        """Get all permanently blocked IPs and their info."""
        result = {}
        current_time = time.time()
        for ip, info in self._permanently_blocked.items():
            result[ip] = info.copy()
            result[ip]["elapsed_seconds"] = int(current_time - info["blocked_at"])
            result[ip]["malicious_count"] = self._malicious_counters.get(ip, 0)
        return result
    
    async def get_blocked_history(self, limit: int = 50) -> list:
        """Get permanent block history from MongoDB."""
        try:
            collection = db.get_collection(self.blocks_collection_name)
            blocks = await collection.find().sort("blocked_at", -1).limit(limit).to_list(length=limit)
            for block in blocks:
                block["_id"] = str(block["_id"])
            return blocks
        except Exception as e:
            logger.error(f"Failed to get block history: {e}")
            return []



# Singleton instance
trap_tracker = TrapTracker()
