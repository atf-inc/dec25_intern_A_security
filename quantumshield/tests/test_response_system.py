import unittest
import asyncio
import sys
import os
import json
import shutil
from unittest.mock import MagicMock, AsyncMock

# Ensure both the project root *and* its parent (which contains the
# 'quantumshield' package directory) are on sys.path so tests work
# whether they are run from the repo root or from this subdirectory.
_current_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_current_dir, ".."))
_workspace_root = os.path.abspath(os.path.join(_project_root, ".."))

for _path in (_project_root, _workspace_root):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from quantumshield.core.response_executor import ResponseExecutor
from response_system.blocking_engine import BlockingEngine
from response_system.rate_limiter import RateLimiter

class TestResponseSystem(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        # Use a temporary file for testing persistence
        self.test_persistence_file = "tests/data/blocked_ips_test.json"
        
        # Clean up previous test runs
        if os.path.exists(self.test_persistence_file):
            os.remove(self.test_persistence_file)
        
    def tearDown(self):
        self.loop.close()
        if os.path.exists(self.test_persistence_file):
            os.remove(self.test_persistence_file)

    def test_blocking_engine_persistence(self):
        engine = BlockingEngine(persistence_file=self.test_persistence_file)
        engine.block_ip("10.0.0.1")
        self.assertTrue(engine.is_blocked("10.0.0.1"))
        
        # Simulate restart by creating new instance loading from same file
        engine2 = BlockingEngine(persistence_file=self.test_persistence_file)
        self.assertTrue(engine2.is_blocked("10.0.0.1"), "Persistence failed check")
        
        engine2.unblock_ip("10.0.0.1")
        self.assertFalse(engine2.is_blocked("10.0.0.1"))

    def test_rate_limiter(self):
        limiter = RateLimiter(default_limit=2)
        ip = "192.168.1.10"
        
        # With limit=2, first two packets are allowed, third should be blocked
        self.assertTrue(limiter.check_rate_limit(ip), "First packet should be allowed")
        self.assertTrue(limiter.check_rate_limit(ip), "Second packet should be allowed")
        self.assertFalse(limiter.check_rate_limit(ip), "Third packet should be blocked")

        # Re-verify logic with fresh instance (same expectations)
        limiter = RateLimiter(default_limit=2)
        ip = "192.168.1.11" # Use different IP
        
        # 1st packet: count=1
        self.assertTrue(limiter.check_rate_limit(ip), "First packet should be allowed")
        
        # 2nd packet: count=2
        self.assertTrue(limiter.check_rate_limit(ip), "Second packet should be allowed")
        
        # 3rd packet: count=3
        self.assertFalse(limiter.check_rate_limit(ip), "Third packet should be blocked")

    def test_response_executor_block(self):
        from quantumshield.core.decision_maker import Decision, ActionType, ThreatContext, ThreatLevel, ConfidenceLevel
        
        executor = ResponseExecutor({})
        executor.blocking_engine = BlockingEngine(persistence_file=self.test_persistence_file)
        
        context = ThreatContext(
            source_ip='1.2.3.4',
            destination_ip='10.0.0.1',
            source_port=12345,
            destination_port=80,
            protocol='TCP'
        )
        
        decision = Decision(
            action=ActionType.BLOCK_PERMANENT,
            confidence=ConfidenceLevel.HIGH,
            threat_level=ThreatLevel.HIGH,
            context=context
        )
        
        self.loop.run_until_complete(executor.execute(decision))
        self.assertTrue(executor.blocking_engine.is_blocked("1.2.3.4"))

if __name__ == '__main__':
    unittest.main()
