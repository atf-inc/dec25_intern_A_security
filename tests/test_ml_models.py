
import unittest
import asyncio
import sys
import os
from unittest.mock import MagicMock, AsyncMock, patch

# Adjust path to AITF_AI root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from quantumshield.ml_models.model_manager import ModelManager

class TestMLModels(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Patch dependencies
        self.settings_patcher = patch('quantumshield.ml_models.model_manager.get_settings')
        self.mock_settings = self.settings_patcher.start()
        self.mock_settings.return_value.ml_enable_gpu = False

        self.tc_patcher = patch('quantumshield.ml_models.model_manager.TrafficClassifier')
        self.mock_tc_cls = self.tc_patcher.start()
        self.mock_tc = self.mock_tc_cls.return_value
        self.mock_tc.load_model = AsyncMock()
        self.mock_tc.infer = AsyncMock(return_value={"threat_score": 0.5, "reason": "suspicious"})

        self.ad_patcher = patch('quantumshield.ml_models.model_manager.AnomalyDetector')
        self.mock_ad_cls = self.ad_patcher.start()
        self.mock_ad = self.mock_ad_cls.return_value
        self.mock_ad.load_model = AsyncMock()
        self.mock_ad.infer = AsyncMock(return_value={"threat_score": 0.2, "reason": "anomaly"})

    async def asyncTearDown(self):
        patch.stopall()

    async def test_initialization(self):
        manager = ModelManager()
        await manager.initialize()
        
        self.assertIn("traffic_classifier", manager.models)
        self.assertIn("anomaly_detector", manager.models)
        self.mock_tc.load_model.assert_awaited_once()
        self.mock_ad.load_model.assert_awaited_once()

    async def test_inference(self):
        manager = ModelManager()
        await manager.initialize()
        
        packet = {"src_ip": "1.2.3.4"}
        flow = {}
        
        result = await manager.infer(packet, flow)
        
        self.assertIsNotNone(result)
        self.assertEqual(result["engine"], "ml")
        # Average of 0.5 and 0.2 is 0.35
        self.assertAlmostEqual(result["threat_score"], 0.35)
        self.assertIn("traffic_classifier: suspicious", result["reason"])
        self.assertIn("anomaly_detector: anomaly", result["reason"])

    async def test_inference_partial_failure(self):
        manager = ModelManager()
        await manager.initialize()
        
        # Simulate traffic classifier failure
        self.mock_tc.infer.side_effect = Exception("Model error")
        
        packet = {"src_ip": "1.2.3.4"}
        flow = {}
        
        # Suppress logger for this test to avoid confusing output
        with patch('quantumshield.ml_models.model_manager.logger') as mock_logger:
            result = await manager.infer(packet, flow)
        
        self.assertIsNotNone(result)
        # Should only have anomaly result (0.2)
        self.assertAlmostEqual(result["threat_score"], 0.2)
        self.assertNotIn("traffic_classifier", result["reason"])
        self.assertIn("anomaly_detector", result["reason"])

if __name__ == "__main__":
    unittest.main()
