#!/usr/bin/env python3
"""
OS-Independent IP Blocking Tracker
Tracks blocked IPs with persistence, time-based blocking, and statistics
Works on both Windows 11 and Kali Linux without external dependencies
"""

import json
import time
import logging
from typing import Dict, Set, List, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)


@dataclass
class BlockEntry:
    """Represents a blocked IP entry"""
    ip: str
    reason: str
    blocked_at: float
    expires_at: Optional[float] = None  # None for permanent blocks
    block_type: str = "permanent"  # "permanent" or "temporary"
    threat_level: str = "medium"
    source: str = "system"  # Where the block originated from
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if the block has expired"""
        if self.expires_at is None:
            return False  # Permanent block
        return time.time() > self.expires_at
    
    def is_active(self) -> bool:
        """Check if the block is currently active"""
        return not self.is_expired()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlockEntry':
        """Create from dictionary"""
        return cls(**data)


class IPBlockingTracker:
    """
    OS-independent IP blocking tracker with persistence.
    Works on both Windows 11 and Kali Linux.
    """
    
    def __init__(self, storage_path: str = "data/blocked_ips.json", 
                 auto_cleanup: bool = True, cleanup_interval: int = 3600):
        """
        Initialize IP blocking tracker.
        
        Args:
            storage_path: Path to JSON file for persistence
            auto_cleanup: Automatically remove expired blocks
            cleanup_interval: Seconds between cleanup operations
        """
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._blocked_ips: Dict[str, BlockEntry] = {}
        self._lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'total_blocks': 0,
            'current_blocks': 0,
            'permanent_blocks': 0,
            'temporary_blocks': 0,
            'auto_unblocks': 0,
            'manual_unblocks': 0,
            'blocks_by_reason': defaultdict(int),
            'blocks_by_source': defaultdict(int),
            'blocks_by_threat_level': defaultdict(int),
        }
        
        self.auto_cleanup = auto_cleanup
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()
        
        # Load existing blocks
        self._load_blocks()
        
        logger.info(f"IP Blocking Tracker initialized with {len(self._blocked_ips)} blocked IPs")
    
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
            source: Source of the block (system, user, rule, etc.)
            metadata: Additional metadata
        
        Returns:
            True if blocked, False if already blocked
        """
        with self._lock:
            # Check if already blocked
            if ip in self._blocked_ips:
                entry = self._blocked_ips[ip]
                if entry.is_active():
                    logger.debug(f"IP {ip} is already blocked")
                    return False
                else:
                    # Remove expired entry
                    del self._blocked_ips[ip]
            
            # Create block entry
            now = time.time()
            expires_at = None if duration is None else now + duration
            block_type = "permanent" if duration is None else "temporary"
            
            entry = BlockEntry(
                ip=ip,
                reason=reason,
                blocked_at=now,
                expires_at=expires_at,
                block_type=block_type,
                threat_level=threat_level,
                source=source,
                metadata=metadata or {}
            )
            
            self._blocked_ips[ip] = entry
            
            # Update statistics
            self.stats['total_blocks'] += 1
            self.stats['current_blocks'] = len(self._get_active_blocks())
            if block_type == "permanent":
                self.stats['permanent_blocks'] += 1
            else:
                self.stats['temporary_blocks'] += 1
            self.stats['blocks_by_reason'][reason] += 1
            self.stats['blocks_by_source'][source] += 1
            self.stats['blocks_by_threat_level'][threat_level] += 1
            
            # Persist
            self._save_blocks()
            
            logger.warning(f"Blocked IP: {ip} | Reason: {reason} | Type: {block_type} | "
                          f"Threat: {threat_level}")
            
            return True
    
    def unblock_ip(self, ip: str, manual: bool = True) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip: IP address to unblock
            manual: True if manually unblocked, False if auto-unblocked
        
        Returns:
            True if unblocked, False if not blocked
        """
        with self._lock:
            if ip not in self._blocked_ips:
                return False
            
            entry = self._blocked_ips[ip]
            del self._blocked_ips[ip]
            
            # Update statistics
            self.stats['current_blocks'] = len(self._get_active_blocks())
            if manual:
                self.stats['manual_unblocks'] += 1
            else:
                self.stats['auto_unblocks'] += 1
            
            # Persist
            self._save_blocks()
            
            logger.info(f"Unblocked IP: {ip} | Type: {'manual' if manual else 'automatic'}")
            
            return True
    
    def is_blocked(self, ip: str) -> bool:
        """
        Check if an IP is currently blocked.
        
        Args:
            ip: IP address to check
        
        Returns:
            True if blocked and active, False otherwise
        """
        with self._lock:
            # Cleanup expired blocks first
            if self.auto_cleanup:
                self._cleanup_expired()
            
            if ip not in self._blocked_ips:
                return False
            
            entry = self._blocked_ips[ip]
            if entry.is_expired():
                # Auto-remove expired
                del self._blocked_ips[ip]
                self.stats['auto_unblocks'] += 1
                self._save_blocks()
                return False
            
            return entry.is_active()
    
    def get_block_info(self, ip: str) -> Optional[BlockEntry]:
        """Get block information for an IP"""
        with self._lock:
            if ip not in self._blocked_ips:
                return None
            
            entry = self._blocked_ips[ip]
            if entry.is_expired():
                del self._blocked_ips[ip]
                self._save_blocks()
                return None
            
            return entry
    
    def get_all_blocked_ips(self, include_expired: bool = False) -> List[BlockEntry]:
        """
        Get all blocked IPs.
        
        Args:
            include_expired: Include expired blocks
        
        Returns:
            List of block entries
        """
        with self._lock:
            if self.auto_cleanup:
                self._cleanup_expired()
            
            if include_expired:
                return list(self._blocked_ips.values())
            else:
                return [entry for entry in self._blocked_ips.values() if entry.is_active()]
    
    def get_blocked_count(self) -> int:
        """Get count of currently blocked IPs"""
        with self._lock:
            if self.auto_cleanup:
                self._cleanup_expired()
            return len(self._get_active_blocks())
    
    def _get_active_blocks(self) -> Dict[str, BlockEntry]:
        """Get dictionary of active blocks"""
        return {ip: entry for ip, entry in self._blocked_ips.items() if entry.is_active()}
    
    def _cleanup_expired(self) -> int:
        """Remove expired blocks and return count of removed blocks"""
        now = time.time()
        
        # Only cleanup if interval has passed
        if now - self.last_cleanup < self.cleanup_interval:
            return 0
        
        self.last_cleanup = now
        
        expired_ips = [
            ip for ip, entry in self._blocked_ips.items()
            if entry.is_expired()
        ]
        
        for ip in expired_ips:
            del self._blocked_ips[ip]
            self.stats['auto_unblocks'] += 1
        
        if expired_ips:
            self.stats['current_blocks'] = len(self._get_active_blocks())
            self._save_blocks()
            logger.info(f"Cleaned up {len(expired_ips)} expired block(s)")
        
        return len(expired_ips)
    
    def cleanup_expired(self) -> int:
        """Manually trigger cleanup of expired blocks"""
        with self._lock:
            return self._cleanup_expired()
    
    def _save_blocks(self) -> None:
        """Save blocked IPs to disk"""
        try:
            data = {
                'version': '1.0',
                'saved_at': time.time(),
                'blocks': [
                    entry.to_dict() for entry in self._blocked_ips.values()
                ],
                'stats': dict(self.stats)
            }
            
            # Atomic write
            temp_path = self.storage_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            temp_path.replace(self.storage_path)
            
        except Exception as e:
            logger.error(f"Failed to save blocked IPs: {e}", exc_info=True)
    
    def _load_blocks(self) -> None:
        """Load blocked IPs from disk"""
        if not self.storage_path.exists():
            return
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            # Load blocks
            blocks_data = data.get('blocks', [])
            for block_data in blocks_data:
                try:
                    entry = BlockEntry.from_dict(block_data)
                    # Only load if not expired
                    if not entry.is_expired():
                        self._blocked_ips[entry.ip] = entry
                except Exception as e:
                    logger.warning(f"Failed to load block entry: {e}")
            
            # Load stats if available
            if 'stats' in data:
                self.stats.update(data['stats'])
                # Update current count
                self.stats['current_blocks'] = len(self._get_active_blocks())
            
            logger.info(f"Loaded {len(self._blocked_ips)} blocked IPs from disk")
            
        except Exception as e:
            logger.error(f"Failed to load blocked IPs: {e}", exc_info=True)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get blocking statistics"""
        with self._lock:
            if self.auto_cleanup:
                self._cleanup_expired()
            
            return {
                **self.stats,
                'current_blocks': len(self._get_active_blocks()),
                'storage_path': str(self.storage_path),
                'last_cleanup': datetime.fromtimestamp(self.last_cleanup).isoformat(),
            }
    
    def clear_all_blocks(self) -> int:
        """Clear all blocked IPs (use with caution)"""
        with self._lock:
            count = len(self._blocked_ips)
            self._blocked_ips.clear()
            self.stats['current_blocks'] = 0
            self._save_blocks()
            logger.warning(f"Cleared all {count} blocked IPs")
            return count
    
    def export_blocks(self, filepath: str) -> bool:
        """Export blocked IPs to a file"""
        try:
            blocks = self.get_all_blocked_ips(include_expired=False)
            data = {
                'exported_at': datetime.now().isoformat(),
                'count': len(blocks),
                'blocks': [entry.to_dict() for entry in blocks]
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Exported {len(blocks)} blocked IPs to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export blocks: {e}", exc_info=True)
            return False
    
    def import_blocks(self, filepath: str, merge: bool = True) -> int:
        """
        Import blocked IPs from a file.
        
        Args:
            filepath: Path to import file
            merge: If True, merge with existing blocks; if False, replace
        
        Returns:
            Number of blocks imported
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            blocks_data = data.get('blocks', [])
            imported = 0
            
            with self._lock:
                if not merge:
                    self._blocked_ips.clear()
                
                for block_data in blocks_data:
                    try:
                        entry = BlockEntry.from_dict(block_data)
                        self._blocked_ips[entry.ip] = entry
                        imported += 1
                    except Exception as e:
                        logger.warning(f"Failed to import block entry: {e}")
                
                self.stats['current_blocks'] = len(self._get_active_blocks())
                self._save_blocks()
            
            logger.info(f"Imported {imported} blocked IPs from {filepath}")
            return imported
            
        except Exception as e:
            logger.error(f"Failed to import blocks: {e}", exc_info=True)
            return 0

