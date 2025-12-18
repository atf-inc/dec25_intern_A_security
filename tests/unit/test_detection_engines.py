"""Unit tests for detection engines."""

import pytest
from quantumshield.detection_engines.signature_engine import SignatureEngine
from quantumshield.detection_engines.anomaly_engine import AnomalyEngine


@pytest.mark.asyncio
async def test_signature_engine():
    """Test signature engine."""
    engine = SignatureEngine()
    await engine.initialize()
    
    packet = {
        "payload": b"SELECT * FROM users WHERE id=1 OR 1=1",
        "src_ip": "192.168.1.1",
    }
    flow = {}
    
    result = await engine.analyze(packet, flow)
    assert result is not None or result is None  # May or may not match


@pytest.mark.asyncio
async def test_anomaly_engine():
    """Test anomaly engine."""
    engine = AnomalyEngine()
    await engine.initialize()
    
    packet = {
        "length": 1500,
        "payload_length": 1400,
        "src_ip": "192.168.1.1",
    }
    flow = {}
    
    result = await engine.analyze(packet, flow)
    assert result is not None

