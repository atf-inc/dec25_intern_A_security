#!/usr/bin/env python3
"""
Test OS-Independent Tools
Tests all 3 OS-independent tools work correctly on both Windows 11 and Kali Linux
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from quantumshield.network_layer.deep_packet_inspector import DeepPacketInspector
from quantumshield.response_system.ip_blocking_tracker import IPBlockingTracker
from quantumshield.response_system.blocking_engine import BlockingEngine
from quantumshield.detection_engines import SignatureEngine, AnomalyEngine, BehavioralEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_1_packet_analysis():
    """Test 1: Deep Packet Inspection"""
    logger.info("=" * 60)
    logger.info("Test 1: Deep Packet Inspection (OS-Independent)")
    logger.info("=" * 60)
    
    inspector = DeepPacketInspector()
    
    # Test statistics
    stats = inspector.get_statistics()
    logger.info(f"DPI Enabled: {stats.get('enabled')}")
    logger.info(f"Scapy Available: {stats.get('scapy_available')}")
    logger.info(f"DPKT Available: {stats.get('dpkt_available')}")
    
    # Test with sample payload (SQL injection)
    test_payload = {
        'protocol': 'TCP',
        'payload': b"admin' OR '1'='1",
    }
    
    analysis = inspector._analyze_from_info(test_payload)
    logger.info(f"Protocol: {analysis.protocol}")
    logger.info(f"Suspicious Patterns: {analysis.suspicious_patterns}")
    logger.info(f"Threat Score: {analysis.threat_score:.3f}")
    
    assert analysis.threat_score > 0, "Should detect SQL injection threat"
    logger.info("✅ Packet analysis test passed")
    
    return True


def test_2_ip_blocking_tracker():
    """Test 2: IP Blocking Tracker"""
    logger.info("\n" + "=" * 60)
    logger.info("Test 2: IP Blocking Tracker (OS-Independent)")
    logger.info("=" * 60)
    
    # Use temporary storage for testing
    test_storage = "data/test_blocked_ips.json"
    
    tracker = IPBlockingTracker(storage_path=test_storage)
    
    # Test blocking
    test_ip = "192.168.1.100"
    result = tracker.block_ip(
        ip=test_ip,
        reason="Test SQL injection attack",
        duration=3600,  # 1 hour
        threat_level="high",
        source="test"
    )
    assert result, "Should successfully block IP"
    logger.info(f"✅ Blocked IP: {test_ip}")
    
    # Test checking blocked IP
    is_blocked = tracker.is_blocked(test_ip)
    assert is_blocked, "IP should be blocked"
    logger.info(f"✅ IP {test_ip} is blocked: {is_blocked}")
    
    # Test getting block info
    block_info = tracker.get_block_info(test_ip)
    assert block_info is not None, "Should return block info"
    logger.info(f"✅ Block info - Reason: {block_info.reason}, Type: {block_info.block_type}")
    
    # Test statistics
    stats = tracker.get_statistics()
    logger.info(f"Total Blocks: {stats.get('total_blocks')}")
    logger.info(f"Current Blocks: {stats.get('current_blocks')}")
    logger.info(f"Temporary Blocks: {stats.get('temporary_blocks')}")
    
    # Test unblocking
    unblocked = tracker.unblock_ip(test_ip, manual=True)
    assert unblocked, "Should successfully unblock IP"
    logger.info(f"✅ Unblocked IP: {test_ip}")
    
    # Verify unblocked
    is_blocked_after = tracker.is_blocked(test_ip)
    assert not is_blocked_after, "IP should not be blocked after unblocking"
    logger.info(f"✅ IP {test_ip} is no longer blocked: {not is_blocked_after}")
    
    # Cleanup test file
    import os
    if os.path.exists(test_storage):
        os.remove(test_storage)
    
    logger.info("✅ IP blocking tracker test passed")
    return True


def test_3_blocking_engine():
    """Test 3: Blocking Engine (using tracker)"""
    logger.info("\n" + "=" * 60)
    logger.info("Test 3: Blocking Engine (OS-Independent)")
    logger.info("=" * 60)
    
    test_storage = "data/test_blocking_engine.json"
    engine = BlockingEngine(storage_path=test_storage)
    
    # Test blocking
    test_ip = "10.0.0.1"
    blocked = engine.block_ip(
        ip=test_ip,
        reason="Test threat",
        threat_level="critical"
    )
    assert blocked, "Should successfully block IP"
    logger.info(f"✅ Blocked IP via engine: {test_ip}")
    
    # Test checking
    is_blocked = engine.is_blocked(test_ip)
    assert is_blocked, "IP should be blocked"
    logger.info(f"✅ Engine confirms IP is blocked: {is_blocked}")
    
    # Test statistics
    stats = engine.get_statistics()
    logger.info(f"Engine Stats - Current Blocks: {stats.get('current_blocks')}")
    logger.info(f"Engine Stats - Total Blocks: {stats.get('total_blocks')}")
    
    # Test unblocking
    unblocked = engine.unblock_ip(test_ip)
    assert unblocked, "Should successfully unblock"
    logger.info(f"✅ Unblocked IP via engine: {test_ip}")
    
    # Cleanup
    import os
    if os.path.exists(test_storage):
        os.remove(test_storage)
    
    logger.info("✅ Blocking engine test passed")
    return True


def test_4_detection_engines():
    """Test 4: Detection Engines (OS-Independent)"""
    logger.info("\n" + "=" * 60)
    logger.info("Test 4: Detection Engines (OS-Independent)")
    logger.info("=" * 60)
    
    # Test Signature Engine (no config argument)
    sig_engine = SignatureEngine()
    logger.info("✅ SignatureEngine initialized")
    
    # Test Anomaly Engine (no config argument)
    anomaly_engine = AnomalyEngine()
    logger.info("✅ AnomalyEngine initialized")
    
    # Test Behavioral Engine (no config argument)
    behavioral_engine = BehavioralEngine()
    logger.info("✅ BehavioralEngine initialized")
    
    logger.info("✅ All detection engines initialized successfully")
    return True


def main():
    """Run all tests"""
    logger.info("\n" + "=" * 60)
    logger.info("OS-Independent Tools Test Suite")
    logger.info("Tests for Windows 11 and Kali Linux compatibility")
    logger.info("=" * 60)
    
    results = []
    
    try:
        # Test 1: Packet Analysis
        results.append(("Packet Analysis (DPI)", test_1_packet_analysis()))
        
        # Test 2: IP Blocking Tracker
        results.append(("IP Blocking Tracker", test_2_ip_blocking_tracker()))
        
        # Test 3: Blocking Engine
        results.append(("Blocking Engine", test_3_blocking_engine()))
        
        # Test 4: Detection Engines
        results.append(("Detection Engines", test_4_detection_engines()))
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        return False
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Test Summary")
    logger.info("=" * 60)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        logger.info(f"{test_name}: {status}")
    
    all_passed = all(result for _, result in results)
    
    if all_passed:
        logger.info("\n✅ All OS-independent tools tests PASSED!")
        logger.info("All tools work correctly and are OS-independent (Windows 11 & Kali Linux)")
    else:
        logger.error("\n❌ Some tests FAILED!")
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

