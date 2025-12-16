"""OSSEC integration."""

from typing import Dict, Any, Optional
from .base_integration import BaseIntegration

class OSSECIntegration(BaseIntegration):
    """Integration with OSSEC HIDS."""
    async def initialize(self): pass
    async def start(self): pass
    async def stop(self): pass
    async def analyze(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]: return None

