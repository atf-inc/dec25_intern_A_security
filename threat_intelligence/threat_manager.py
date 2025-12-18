"""
Threat Manager
Central component for IP reputation and threat intelligence management.
"""

import asyncio
import logging
from typing import Set, Optional
from .feed_aggregator import ThreatFeedAggregator

logger = logging.getLogger(__name__)

class ThreatManager:
    """Manages threat intelligence feeds and IP reputation."""
    
    def __init__(self):
        self.aggregator = ThreatFeedAggregator()
        self.malicious_ips: Set[str] = set()
        self.running = False
        self._background_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the threat manager and background updates."""
        self.running = True
        # Initial load
        await self.update_intelligence()
        # Start periodic updates
        self._background_task = asyncio.create_task(self._periodic_update())
        logger.info("Threat Manager started")

    async def stop(self):
        """Stop the threat manager."""
        self.running = False
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
        logger.info("Threat Manager stopped")

    async def _periodic_update(self):
        """Periodically update threat intelligence in the background."""
        while self.running:
            try:
                await asyncio.sleep(3600)  # Update every hour
                await self.update_intelligence()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic threat update: {e}")
                await asyncio.sleep(60)  # Retry sooner on error

    async def update_intelligence(self):
        """Trigger an immediate update of threat feeds."""
        logger.info("Starting manual threat intelligence update...")
        try:
            self.malicious_ips = await self.aggregator.update_feeds()
            logger.info(f"Threat intelligence updated. Active rules: {len(self.malicious_ips)}")
        except Exception as e:
            logger.error(f"Failed to update threat intelligence: {e}")

    def is_malicious(self, ip: str) -> bool:
        """Check if an IP is known to be malicious."""
        return ip in self.malicious_ips

    def get_stats(self):
        """Return statistics about the threat manager."""
        return {
            "total_malicious_ips": len(self.malicious_ips),
            "feeds_configured": len(self.aggregator.FEEDS)
        }
