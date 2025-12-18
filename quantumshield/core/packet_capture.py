"""
Packet capture abstraction used by QuantumShieldEngine.

This implementation is intentionally conservative and designed to be
safe to run on all platforms (including Windows) without requiring raw
socket privileges. For now it acts as a stub that can be extended
later to use scapy/pyshark when available.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Minimal packet capture component.

    The goal of this class is to provide the interface expected by
    `core.engine.QuantumShieldEngine`:
      - async start()
      - async stop()
      - async capture_batch(batch_size: int) -> List[Any]

    In this stub implementation we simply return an empty list so that
    the rest of the pipeline can run without requiring real network
    capture. You can later plug in scapy / pyshark based capture here.
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.interface = self.config.get("interface")
        self.enabled = bool(self.config.get("enabled", False))
        self.running = False

    async def start(self) -> None:
        """Start packet capture (no‑op if disabled)."""
        if self.running:
            logger.debug("PacketCapture already running")
            return

        self.running = True
        if not self.enabled:
            logger.info(
                "PacketCapture started in DISABLED mode (no real packets will be captured)"
            )
        else:
            logger.info(
                "PacketCapture started on interface %s (stub implementation)",
                self.interface or "<auto>",
            )

    async def stop(self) -> None:
        """Stop packet capture."""
        if not self.running:
            return

        self.running = False
        logger.info("PacketCapture stopped")

    async def capture_batch(self, batch_size: int = 100) -> List[Any]:
        """
        Capture a batch of packets.

        In this stub we simply sleep briefly and return an empty list,
        which keeps the engine loops active without generating traffic.
        """
        if not self.running or not self.enabled:
            # Small sleep to avoid tight loop in the engine
            await asyncio.sleep(0.01)
            return []

        # Real implementation would capture packets here.
        await asyncio.sleep(0.01)
        return []


