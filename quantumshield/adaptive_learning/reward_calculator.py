"""
Reward Calculator for Reinforcement Learning
Calculates rewards based on decision outcomes and attack prevention success
"""

import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging

from ..core.decision_maker import Decision, ActionType, ThreatLevel, ThreatContext

logger = logging.getLogger(__name__)


class RewardCalculator:
    """Calculates rewards for RL agent based on decision outcomes."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Reward weights
        self.weights = self.config.get('weights', {
            'attack_prevented': 10.0,
            'attack_detected': 5.0,
            'false_positive': -3.0,
            'false_negative': -10.0,
            'correct_allow': 1.0,
            'correct_block': 8.0,
            'over_blocking': -2.0,
            'under_blocking': -5.0,
            'response_time': -0.1,  # Penalty for slow response
            'resource_usage': -0.05  # Penalty for high resource usage
        })
        
        # Feedback tracking
        self.feedback_history: Dict[str, Dict[str, Any]] = {}
        self.feedback_window = self.config.get('feedback_window', 3600)  # 1 hour
        
        # Attack pattern tracking
        self.attack_patterns: Dict[str, Dict[str, Any]] = {}
    
    def calculate_reward(self, 
                       decision: Decision,
                       context: ThreatContext,
                       outcome: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculate reward for a decision.
        
        Args:
            decision: The decision made
            context: Threat context
            outcome: Optional outcome information (attack_prevented, false_positive, etc.)
        
        Returns:
            Reward value
        """
        reward = 0.0
        
        # Base reward from decision correctness
        if outcome:
            reward += self._calculate_outcome_reward(decision, context, outcome)
        else:
            # Estimate reward from decision characteristics
            reward += self._estimate_reward(decision, context)
        
        # Temporal reward (faster detection is better)
        reward += self._calculate_temporal_reward(decision, context)
        
        # Resource efficiency reward
        reward += self._calculate_resource_reward(decision, context)
        
        # Pattern recognition reward
        reward += self._calculate_pattern_reward(decision, context)
        
        return reward
    
    def _calculate_outcome_reward(self, 
                                 decision: Decision,
                                 context: ThreatContext,
                                 outcome: Dict[str, Any]) -> float:
        """Calculate reward based on actual outcome."""
        reward = 0.0
        
        # Attack prevented
        if outcome.get('attack_prevented', False):
            reward += self.weights['attack_prevented']
            if decision.action in [ActionType.BLOCK_PERMANENT, ActionType.BLOCK_TEMPORARY]:
                reward += self.weights['correct_block']
        
        # Attack detected but not prevented
        elif outcome.get('attack_detected', False):
            reward += self.weights['attack_detected']
            if decision.action == ActionType.ALLOW:
                reward += self.weights['false_negative']
        
        # False positive (blocked legitimate traffic)
        elif outcome.get('false_positive', False):
            reward += self.weights['false_positive']
            if decision.action in [ActionType.BLOCK_PERMANENT, ActionType.BLOCK_TEMPORARY]:
                reward += self.weights['over_blocking']
        
        # Correct allow (legitimate traffic allowed)
        elif outcome.get('correct_allow', False):
            reward += self.weights['correct_allow']
        
        # False negative (missed attack)
        elif outcome.get('false_negative', False):
            reward += self.weights['false_negative']
            if decision.action == ActionType.ALLOW:
                reward += self.weights['under_blocking']
        
        return reward
    
    def _estimate_reward(self, 
                        decision: Decision,
                        context: ThreatContext) -> float:
        """Estimate reward when outcome is unknown."""
        reward = 0.0
        
        # Reward based on threat level and action alignment
        threat_level = decision.threat_level.value
        action_severity = self._get_action_severity(decision.action)
        
        # Good alignment: high threat -> strong action
        if threat_level >= ThreatLevel.HIGH.value and action_severity >= 3:
            reward += 5.0
        elif threat_level >= ThreatLevel.CRITICAL.value and action_severity >= 4:
            reward += 8.0
        
        # Bad alignment: high threat -> weak action
        if threat_level >= ThreatLevel.HIGH.value and action_severity < 2:
            reward -= 5.0
        
        # Bad alignment: low threat -> strong action (over-blocking)
        if threat_level <= ThreatLevel.LOW.value and action_severity >= 3:
            reward -= 2.0
        
        # Confidence bonus
        confidence_value = decision.confidence.value
        if confidence_value >= 4:  # HIGH or VERY_HIGH
            reward += 1.0
        elif confidence_value <= 2:  # LOW or VERY_LOW
            reward -= 1.0
        
        return reward
    
    def _get_action_severity(self, action: ActionType) -> int:
        """Get severity level of action (0-5)."""
        severity_map = {
            ActionType.ALLOW: 0,
            ActionType.LOG: 1,
            ActionType.ALERT: 1,
            ActionType.RATE_LIMIT: 2,
            ActionType.THROTTLE: 2,
            ActionType.CHALLENGE: 2,
            ActionType.BLOCK_TEMPORARY: 3,
            ActionType.REDIRECT: 3,
            ActionType.HONEYPOT_REDIRECT: 3,
            ActionType.QUARANTINE: 4,
            ActionType.BLOCK_PERMANENT: 4,
            ActionType.DROP_SILENT: 4,
            ActionType.RESET_CONNECTION: 3
        }
        return severity_map.get(action, 1)
    
    def _calculate_temporal_reward(self,
                                  decision: Decision,
                                  context: ThreatContext) -> float:
        """Calculate reward based on response time."""
        # Faster detection is better
        detection_time = context.last_seen - context.start_time
        
        # Ideal detection time: < 1 second
        if detection_time < 1.0:
            return 1.0
        elif detection_time < 5.0:
            return 0.5
        elif detection_time < 30.0:
            return 0.0
        else:
            # Penalty for slow detection
            return -0.5 * (detection_time / 60.0)
    
    def _calculate_resource_reward(self,
                                   decision: Decision,
                                   context: ThreatContext) -> float:
        """Calculate reward based on resource efficiency."""
        reward = 0.0
        
        # Prefer lighter actions when threat is low
        if decision.threat_level.value <= ThreatLevel.LOW.value:
            if decision.action in [ActionType.ALLOW, ActionType.LOG]:
                reward += 0.5  # Efficient
        
        # Prefer stronger actions when threat is high
        if decision.threat_level.value >= ThreatLevel.HIGH.value:
            if decision.action in [ActionType.BLOCK_PERMANENT, ActionType.QUARANTINE]:
                reward += 0.5  # Appropriate
        
        return reward
    
    def _calculate_pattern_reward(self,
                                 decision: Decision,
                                 context: ThreatContext) -> float:
        """Calculate reward based on pattern recognition."""
        reward = 0.0
        
        # Bonus for recognizing known attack patterns
        if context.indicators:
            indicator_types = set(ind.indicator_type for ind in context.indicators)
            
            # Known attack patterns
            known_patterns = {
                'sql_injection', 'xss', 'command_injection',
                'ddos', 'port_scan', 'malware'
            }
            
            if indicator_types.intersection(known_patterns):
                reward += 1.0
        
        return reward
    
    def record_feedback(self,
                      decision_id: str,
                      feedback: Dict[str, Any]) -> None:
        """Record feedback for a decision."""
        self.feedback_history[decision_id] = {
            'feedback': feedback,
            'timestamp': time.time()
        }
        
        # Cleanup old feedback
        self._cleanup_old_feedback()
    
    def get_feedback(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Get feedback for a decision."""
        if decision_id in self.feedback_history:
            return self.feedback_history[decision_id]['feedback']
        return None
    
    def _cleanup_old_feedback(self) -> None:
        """Remove old feedback entries."""
        current_time = time.time()
        to_remove = [
            decision_id for decision_id, data in self.feedback_history.items()
            if current_time - data['timestamp'] > self.feedback_window
        ]
        
        for decision_id in to_remove:
            del self.feedback_history[decision_id]
    
    def update_attack_pattern(self,
                            pattern_id: str,
                            pattern_data: Dict[str, Any]) -> None:
        """Update or add an attack pattern."""
        self.attack_patterns[pattern_id] = {
            **pattern_data,
            'last_seen': time.time(),
            'count': self.attack_patterns.get(pattern_id, {}).get('count', 0) + 1
        }
    
    def get_pattern_reward(self, pattern_id: str) -> float:
        """Get reward bonus for recognizing a known pattern."""
        if pattern_id in self.attack_patterns:
            pattern = self.attack_patterns[pattern_id]
            # More frequently seen patterns get higher reward
            count = pattern.get('count', 1)
            return min(count / 10.0, 2.0)  # Max 2.0 bonus
        return 0.0
    
    def calculate_delayed_reward(self,
                                decision: Decision,
                                context: ThreatContext,
                                time_elapsed: float) -> float:
        """
        Calculate reward after some time has elapsed.
        Useful for delayed feedback scenarios.
        """
        base_reward = self.calculate_reward(decision, context)
        
        # Apply time decay
        decay_factor = 1.0 / (1.0 + time_elapsed / 3600.0)  # Decay over hours
        return base_reward * decay_factor

