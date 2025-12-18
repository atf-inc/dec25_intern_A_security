
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import unittest
from quantumshield.core.engine import QuantumShieldEngine
from quantumshield.core.decision_maker import DecisionMaker
from quantumshield.core.traffic_processor import AsyncTrafficProcessor

class TestCoreModule(unittest.IsolatedAsyncioTestCase):
    async def test_engine_initialization(self):
        config = {
            'capture': {'enabled': False},
            'processor': {},
            'decision': {},
            'response': {},
            'detection_engines': {
                'signature': {'enabled': True},
                'anomaly': {'enabled': True},
                'behavioral': {'enabled': True}
            }
        }
        engine = QuantumShieldEngine(config)
        self.assertEqual(engine.config, config)
        self.assertIsInstance(engine.decision_maker, DecisionMaker)
        self.assertIsInstance(engine.traffic_processor, AsyncTrafficProcessor)

    async def test_engine_component_loading(self):
        import sys
        import inspect
        sys.stderr.write(f"DEBUG: QuantumShieldEngine file: {inspect.getfile(QuantumShieldEngine)}\n")
        
        config = {
            'capture': {'enabled': False},
            'processor': {},
            'decision': {},
            'response': {},
            'detection_engines': {
                'signature': {'enabled': True},
                'anomaly': {'enabled': False},
                'behavioral': {'enabled': False}
            }
        }
        engine = QuantumShieldEngine(config)
        sys.stderr.write("DEBUG: Calling _load_detection_engines\n")
        await engine._load_detection_engines()
        sys.stderr.write(f"DEBUG: Detection engines count: {len(engine.detection_engines)}\n")
        self.assertEqual(len(engine.detection_engines), 1)

    async def test_decision_maker(self):
        dm = DecisionMaker()
        from quantumshield.core.decision_maker import ThreatContext, ThreatLevel, ActionType, ThreatIndicator
        
        context = ThreatContext(
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=1234,
            destination_port=80,
            protocol="TCP"
        )
        indicators = [
            ThreatIndicator(
                name="Test",
                confidence=0.9,
                severity=ThreatLevel.HIGH,
                source="Test"
            )
        ]
        
        decision = await dm.make_decision(context, indicators)
        self.assertIn(decision.action, [ActionType.BLOCK_TEMPORARY, ActionType.BLOCK_PERMANENT])

if __name__ == "__main__":
    unittest.main()
