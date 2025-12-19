import unittest
import asyncio
import sys
import os
from unittest.mock import MagicMock, patch, AsyncMock

# Adjust path to import modules from root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threat_intelligence.threat_manager import ThreatManager
from threat_intelligence.feed_aggregator import ThreatFeedAggregator

class TestThreatIntelligence(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    @patch('aiohttp.ClientSession.get')
    def test_feed_aggregator_fetch(self, mock_get):
        # Mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "1.2.3.4\n5.6.7.8 # Comment"
        mock_get.return_value.__aenter__.return_value = mock_response

        aggregator = ThreatFeedAggregator()
        aggregator.FEEDS = ["http://mock.feed"]
        
        ips = self.loop.run_until_complete(aggregator.update_feeds())
        
        self.assertIn("1.2.3.4", ips)
        self.assertIn("5.6.7.8", ips)
        self.assertEqual(len(ips), 2)

    @patch('threat_intelligence.threat_manager.ThreatFeedAggregator.update_feeds')
    def test_threat_manager_update(self, mock_update):
        mock_update.return_value = {"10.0.0.1", "192.168.1.1"}
        
        manager = ThreatManager()
        self.loop.run_until_complete(manager.update_intelligence())
        
        self.assertTrue(manager.is_malicious("10.0.0.1"))
        self.assertFalse(manager.is_malicious("8.8.8.8"))
        self.assertEqual(manager.get_stats()['total_malicious_ips'], 2)

    def test_integration_init(self):
        # Test that manager initializes correctly without error
        manager = ThreatManager()
        stats = manager.get_stats()
        self.assertIn("total_malicious_ips", stats)

if __name__ == '__main__':
    unittest.main()
