"""Aggregate threat intelligence feeds."""

import asyncio
import aiohttp
import re
from typing import Set, List
try:
    from config.logging_config import get_logger
except ImportError:
    # Handle case where config is not found or use default logger
    import logging
    get_logger = logging.getLogger

logger = get_logger(__name__)

class ThreatFeedAggregator:
    """Aggregate threat intelligence from multiple feeds."""
    
    # Publicly available free blocklists
    FEEDS = [
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset"
    ]

    def __init__(self):
        """Initialize feed aggregator."""
        self.malicious_ips: Set[str] = set()

    async def fetch_feed(self, session: aiohttp.ClientSession, url: str) -> Set[str]:
        """Fetch and parse a single feed."""
        ips = set()
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    # Extract IPs (simple regex for IPv4)
                    found_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
                    # Filter out non-public or invalid IPs if necessary
                    ips.update(found_ips)
                    logger.debug(f"Fetched {len(found_ips)} IPs from {url}")
                else:
                    logger.warning(f"Failed to fetch {url}: Status {response.status}")
        except Exception as e:
            logger.error(f"Error fetching feed {url}: {e}")
        return ips

    async def update_feeds(self) -> Set[str]:
        """Update threat intelligence feeds and return the set of malicious IPs."""
        logger.info("Updating threat intelligence feeds...")
        new_ips = set()
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_feed(session, url) for url in self.FEEDS]
            results = await asyncio.gather(*tasks)
            
            for result in results:
                new_ips.update(result)
        
        self.malicious_ips = new_ips
        logger.info(f"Threat feeds updated. Total unique malicious IPs: {len(self.malicious_ips)}")
        return self.malicious_ips
