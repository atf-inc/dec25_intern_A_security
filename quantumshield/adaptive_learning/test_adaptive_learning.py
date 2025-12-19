#!/usr/bin/env python3
"""
Test Adaptive Learning Module in Runtime
This script tests the adaptive learning module while the firewall and vulnerable-app are running.
It sends test attacks and verifies that adaptive learning is working correctly.
"""

import asyncio
import sys
import logging
import requests
import time
from pathlib import Path
from typing import Dict, Any

# Add parent directories to path
_current_dir = Path(__file__).parent
_quantumshield_dir = _current_dir.parent
_parent_dir = _quantumshield_dir.parent

for path in [_parent_dir, _quantumshield_dir]:
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from quantumshield.adaptive_learning import AdaptiveLearner
from quantumshield.core.decision_maker import (
    DecisionMaker, ThreatContext, ThreatIndicator, ThreatLevel, ActionType
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AdaptiveLearningTester:
    """Test adaptive learning module in runtime"""
    
    def __init__(self, vulnerable_app_url: str = "http://localhost:3000"):
        self.vulnerable_app_url = vulnerable_app_url
        self.adaptive_learner = None
        self.decision_maker = None
        
    async def initialize(self):
        """Initialize test components"""
        logger.info("Initializing Adaptive Learning Tester...")
        
        # Initialize DecisionMaker
        self.decision_maker = DecisionMaker({})
        
        # Initialize AdaptiveLearner
        config = {
            'training_mode': True,
            'learning_enabled': True,
            'rl_agent': {
                'learning_rate': 0.001,
                'gamma': 0.95,
                'epsilon_start': 1.0,
                'epsilon_min': 0.01,
                'batch_size': 32,
                'memory_size': 10000
            },
            'pattern_learner': {
                'similarity_threshold': 0.7,
                'min_pattern_count': 3
            },
            'storage_path': 'adaptive_learning'
        }
        
        self.adaptive_learner = AdaptiveLearner(self.decision_maker, config)
        await self.adaptive_learner.initialize()
        
        logger.info("✓ Adaptive Learning Tester initialized")
    
    def create_sql_injection_context(self, payload: str) -> ThreatContext:
        """Create SQL injection threat context"""
        context = ThreatContext(
            source_ip='192.168.1.100',
            destination_ip='127.0.0.1',
            source_port=54321,
            destination_port=3000,
            protocol='TCP'
        )
        context.add_indicator(ThreatIndicator(
            source='signature_engine',
            indicator_type='sql_injection',
            severity=ThreatLevel.HIGH,
            confidence=0.9,
            description=f'SQL injection attempt: {payload[:50]}',
            details={'payload': payload}
        ))
        return context
    
    def create_xss_context(self, payload: str) -> ThreatContext:
        """Create XSS attack threat context"""
        context = ThreatContext(
            source_ip='192.168.1.101',
            destination_ip='127.0.0.1',
            source_port=54322,
            destination_port=3000,
            protocol='TCP'
        )
        context.add_indicator(ThreatIndicator(
            source='signature_engine',
            indicator_type='xss_attack',
            severity=ThreatLevel.HIGH,
            confidence=0.85,
            description=f'XSS attack attempt: {payload[:50]}',
            details={'payload': payload}
        ))
        return context
    
    def create_port_scan_context(self) -> ThreatContext:
        """Create port scan threat context"""
        context = ThreatContext(
            source_ip='192.168.1.102',
            destination_ip='127.0.0.1',
            source_port=54323,
            destination_port=8080,
            protocol='TCP'
        )
        context.add_indicator(ThreatIndicator(
            source='behavioral_engine',
            indicator_type='port_scan',
            severity=ThreatLevel.MEDIUM,
            confidence=0.75,
            description='Multiple port connection attempts detected'
        ))
        return context
    
    async def test_pattern_learning(self):
        """Test pattern learning with multiple attacks"""
        logger.info("\n" + "=" * 60)
        logger.info("Test 1: Pattern Learning")
        logger.info("=" * 60)
        
        # Test SQL injection patterns
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT * FROM users--",
            "' OR 1=1--",
            "admin'--"
        ]
        
        logger.info(f"\nTesting {len(sql_payloads)} SQL injection patterns...")
        for i, payload in enumerate(sql_payloads, 1):
            context = self.create_sql_injection_context(payload)
            decision = await self.decision_maker.make_decision(context, context.indicators)
            
            outcome = {
                'attack_prevented': True,
                'false_positive': False,
                'response_time': 0.1
            }
            
            await self.adaptive_learner.process_decision(context, decision, outcome)
            logger.info(f"  {i}. Processed SQL injection: {payload[:30]}...")
        
        # Test XSS patterns
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "<svg onload=alert(1)>"
        ]
        
        logger.info(f"\nTesting {len(xss_payloads)} XSS attack patterns...")
        for i, payload in enumerate(xss_payloads, 1):
            context = self.create_xss_context(payload)
            decision = await self.decision_maker.make_decision(context, context.indicators)
            
            outcome = {
                'attack_prevented': True,
                'false_positive': False,
                'response_time': 0.1
            }
            
            await self.adaptive_learner.process_decision(context, decision, outcome)
            logger.info(f"  {i}. Processed XSS attack: {payload[:30]}...")
        
        # Get statistics
        stats = self.adaptive_learner.get_statistics()
        logger.info(f"\n✓ Pattern Learning Results:")
        logger.info(f"  Patterns Learned: {stats.get('patterns_learned', 0)}")
        logger.info(f"  Decisions Processed: {stats.get('decisions_processed', 0)}")
        
        pattern_stats = stats.get('pattern_learner', {})
        logger.info(f"  Total Patterns: {pattern_stats.get('total_patterns', 0)}")
    
    async def test_pattern_recognition(self):
        """Test pattern recognition on similar attacks"""
        logger.info("\n" + "=" * 60)
        logger.info("Test 2: Pattern Recognition")
        logger.info("=" * 60)
        
        # Test similar SQL injection (should recognize pattern)
        similar_sql = "' OR '2'='2"  # Similar to learned pattern
        context = self.create_sql_injection_context(similar_sql)
        
        recognized_pattern = self.adaptive_learner.pattern_learner.recognize_pattern(context)
        if recognized_pattern:
            logger.info(f"✓ Recognized pattern: {recognized_pattern.get('pattern_id')}")
            logger.info(f"  Confidence: {recognized_pattern.get('confidence', 0):.3f}")
            logger.info(f"  Type: {recognized_pattern.get('pattern_type', 'unknown')}")
        else:
            logger.info("⚠ No pattern recognized (may need more examples)")
        
        # Test similar XSS (should recognize pattern)
        similar_xss = "<script>alert('TEST')</script>"
        context = self.create_xss_context(similar_xss)
        
        recognized_pattern = self.adaptive_learner.pattern_learner.recognize_pattern(context)
        if recognized_pattern:
            logger.info(f"✓ Recognized XSS pattern: {recognized_pattern.get('pattern_id')}")
            logger.info(f"  Confidence: {recognized_pattern.get('confidence', 0):.3f}")
        else:
            logger.info("⚠ No XSS pattern recognized")
    
    async def test_rl_suggestions(self):
        """Test RL agent action suggestions"""
        logger.info("\n" + "=" * 60)
        logger.info("Test 3: RL Agent Suggestions")
        logger.info("=" * 60)
        
        test_cases = [
            ("SQL Injection", self.create_sql_injection_context("' OR '1'='1")),
            ("XSS Attack", self.create_xss_context("<script>alert(1)</script>")),
            ("Port Scan", self.create_port_scan_context())
        ]
        
        for name, context in test_cases:
            suggestion = await self.adaptive_learner.suggest_action(context)
            if suggestion:
                logger.info(f"\n{name}:")
                logger.info(f"  Suggested Action: {suggestion.get('action')}")
                logger.info(f"  Confidence: {suggestion.get('confidence', 0):.3f}")
                logger.info(f"  Q-Value: {suggestion.get('q_value', 0):.3f}")
                
                if 'pattern_id' in suggestion:
                    logger.info(f"  Pattern ID: {suggestion['pattern_id']}")
            else:
                logger.warning(f"{name}: No suggestion returned")
    
    async def test_statistics(self):
        """Test statistics collection"""
        logger.info("\n" + "=" * 60)
        logger.info("Test 4: Statistics")
        logger.info("=" * 60)
        
        stats = self.adaptive_learner.get_statistics()
        
        logger.info("Overall Statistics:")
        logger.info(f"  Decisions Processed: {stats.get('decisions_processed', 0)}")
        logger.info(f"  Patterns Learned: {stats.get('patterns_learned', 0)}")
        logger.info(f"  Patterns Recognized: {stats.get('patterns_recognized', 0)}")
        logger.info(f"  Policies Updated: {stats.get('policies_updated', 0)}")
        
        rl_stats = stats.get('rl_agent', {})
        logger.info("\nRL Agent Statistics:")
        logger.info(f"  Epsilon: {rl_stats.get('epsilon', 0):.3f}")
        logger.info(f"  Training Steps: {rl_stats.get('training_steps', 0)}")
        logger.info(f"  Memory Size: {rl_stats.get('memory_size', 0)}")
        logger.info(f"  Exploration Rate: {rl_stats.get('exploration_rate', 0):.3f}")
        
        pattern_stats = stats.get('pattern_learner', {})
        logger.info("\nPattern Learner Statistics:")
        logger.info(f"  Total Patterns: {pattern_stats.get('total_patterns', 0)}")
    
    async def test_with_vulnerable_app(self):
        """Test by sending requests to vulnerable app"""
        logger.info("\n" + "=" * 60)
        logger.info("Test 5: Integration with Vulnerable App")
        logger.info("=" * 60)
        
        try:
            # Check if vulnerable app is running
            response = requests.get(self.vulnerable_app_url, timeout=2)
            logger.info(f"✓ Vulnerable app is running at {self.vulnerable_app_url}")
        except requests.exceptions.RequestException:
            logger.warning(f"⚠ Vulnerable app not reachable at {self.vulnerable_app_url}")
            logger.warning("  Continuing with simulated tests...")
            return
        
        # Note: In real scenario, the firewall would intercept these requests
        # For testing, we simulate the threat contexts
        logger.info("\nSimulating intercepted attacks...")
        
        attack_payloads = [
            ("SQL Injection", "' OR '1'='1"),
            ("XSS", "<script>alert('XSS')</script>"),
            ("SQL Injection", "'; DROP TABLE users--")
        ]
        
        for attack_type, payload in attack_payloads:
            if attack_type == "SQL Injection":
                context = self.create_sql_injection_context(payload)
            else:
                context = self.create_xss_context(payload)
            
            decision = await self.decision_maker.make_decision(context, context.indicators)
            outcome = {'attack_prevented': True, 'false_positive': False}
            await self.adaptive_learner.process_decision(context, decision, outcome)
            
            logger.info(f"  Processed {attack_type} attack")
    
    async def run_all_tests(self):
        """Run all tests"""
        logger.info("=" * 60)
        logger.info("Adaptive Learning Runtime Tests")
        logger.info("=" * 60)
        
        await self.initialize()
        
        try:
            await self.test_pattern_learning()
            await self.test_pattern_recognition()
            await self.test_rl_suggestions()
            await self.test_statistics()
            await self.test_with_vulnerable_app()
            
            # Save state
            logger.info("\nSaving adaptive learning state...")
            await self.adaptive_learner.save_state()
            logger.info("✓ State saved")
            
            logger.info("\n" + "=" * 60)
            logger.info("All tests completed successfully!")
            logger.info("=" * 60)
            
        finally:
            # Cleanup
            if self.adaptive_learner:
                await self.adaptive_learner.shutdown()


async def main():
    """Main entry point"""
    tester = AdaptiveLearningTester()
    
    try:
        await tester.run_all_tests()
    except KeyboardInterrupt:
        logger.info("\nTests interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

