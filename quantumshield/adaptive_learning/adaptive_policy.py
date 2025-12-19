"""
Adaptive Policy Updater
Updates security policies based on learned patterns and RL feedback
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import time

from ..core.decision_maker import Policy, ActionType, ThreatLevel, DecisionMaker

logger = logging.getLogger(__name__)


class AdaptivePolicyUpdater:
    """Updates policies based on learned patterns and feedback."""
    
    def __init__(self, 
                 decision_maker: DecisionMaker,
                 config: Optional[Dict[str, Any]] = None):
        self.decision_maker = decision_maker
        self.config = config or {}
        
        # Update thresholds
        self.min_confidence = self.config.get('min_confidence', 0.7)
        self.min_pattern_count = self.config.get('min_pattern_count', 5)
        self.update_interval = self.config.get('update_interval', 3600)  # 1 hour
        
        # Policy update history
        self.update_history: List[Dict[str, Any]] = []
        self.last_update = time.time()
        
        # Statistics
        self.stats = {
            'policies_created': 0,
            'policies_updated': 0,
            'policies_removed': 0,
            'threshold_adjustments': 0
        }
    
    def update_policies_from_patterns(self,
                                     patterns: Dict[str, Any],
                                     rl_recommendations: Optional[Dict[str, Any]] = None) -> None:
        """
        Update policies based on learned patterns.
        
        Args:
            patterns: Dictionary of learned patterns
            rl_recommendations: Optional RL agent recommendations
        """
        current_time = time.time()
        
        # Check if enough time has passed
        if current_time - self.last_update < self.update_interval:
            return
        
        logger.info("Updating policies from learned patterns")
        
        # Create/update policies for high-confidence patterns
        for pattern_id, pattern_data in patterns.items():
            if self._should_create_policy(pattern_data):
                self._create_policy_from_pattern(pattern_id, pattern_data)
        
        # Update existing policies based on RL feedback
        if rl_recommendations:
            self._update_policies_from_rl(rl_recommendations)
        
        # Remove outdated policies
        self._cleanup_outdated_policies()
        
        self.last_update = current_time
    
    def _should_create_policy(self, pattern_data: Dict[str, Any]) -> bool:
        """Check if a policy should be created for this pattern."""
        confidence = pattern_data.get('confidence', 0.0)
        count = pattern_data.get('count', 0)
        
        return (
            confidence >= self.min_confidence and
            count >= self.min_pattern_count
        )
    
    def _create_policy_from_pattern(self,
                                   pattern_id: str,
                                   pattern_data: Dict[str, Any]) -> None:
        """Create a new policy from a learned pattern."""
        pattern_type = pattern_data.get('pattern_type', 'unknown')
        features = pattern_data.get('features', {})
        recommended_action = pattern_data.get('recommended_action')
        success_rate = pattern_data.get('success_rate', 0.0)
        
        if not recommended_action:
            return
        
        # Determine threat level from pattern
        indicators = features.get('indicators', {})
        max_severity = indicators.get('max_severity', 2)
        
        threat_level_map = {
            1: ThreatLevel.LOW,
            2: ThreatLevel.MEDIUM,
            3: ThreatLevel.HIGH,
            4: ThreatLevel.CRITICAL,
            5: ThreatLevel.EMERGENCY
        }
        threat_level = threat_level_map.get(max_severity, ThreatLevel.MEDIUM)
        
        # Build conditions
        conditions = {}
        
        # Protocol condition
        if features.get('network', {}).get('protocol'):
            conditions['protocol'] = [features['network']['protocol']]
        
        # Port condition
        if features.get('network', {}).get('dst_port'):
            conditions['destination_port'] = features['network']['dst_port']
        
        # Indicator types
        indicator_types = features.get('indicators', {}).get('types', [])
        if indicator_types:
            conditions['indicator_types'] = indicator_types
        
        # Determine actions
        actions = [recommended_action]
        if threat_level.value >= ThreatLevel.HIGH.value:
            actions.append(ActionType.ALERT)
        actions.append(ActionType.LOG)
        
        # Create policy
        policy = Policy(
            policy_id=f"adaptive_{pattern_id}",
            name=f"Adaptive Policy: {pattern_type}",
            description=f"Auto-generated policy for {pattern_type} pattern (confidence={pattern_data.get('confidence', 0):.2f}, success={success_rate:.2f})",
            priority=700 + int(success_rate * 100),  # Higher success = higher priority
            enabled=True,
            conditions=conditions,
            actions=actions,
            parameters={
                'pattern_id': pattern_id,
                'pattern_type': pattern_type,
                'confidence': pattern_data.get('confidence', 0.0),
                'success_rate': success_rate,
                'created_from': 'adaptive_learning',
                'created_at': time.time()
            }
        )
        
        # Check if policy already exists
        existing_policy = None
        for p in self.decision_maker.policy_engine.policies:
            if p.policy_id == policy.policy_id:
                existing_policy = p
                break
        
        if existing_policy:
            # Update existing policy
            self.decision_maker.policy_engine.update_policy(policy)
            self.stats['policies_updated'] += 1
            logger.info(f"Updated adaptive policy: {policy.policy_id}")
        else:
            # Add new policy
            self.decision_maker.add_policy(policy)
            self.stats['policies_created'] += 1
            logger.info(f"Created adaptive policy: {policy.policy_id}")
        
        # Record update
        self.update_history.append({
            'pattern_id': pattern_id,
            'policy_id': policy.policy_id,
            'action': 'created' if not existing_policy else 'updated',
            'timestamp': time.time()
        })
    
    def _update_policies_from_rl(self, rl_recommendations: Dict[str, Any]) -> None:
        """Update policies based on RL agent recommendations."""
        # This would update policy parameters based on RL feedback
        # For example, adjusting thresholds or action priorities
        
        for policy_id, recommendations in rl_recommendations.items():
            # Find policy
            policy = None
            for p in self.decision_maker.policy_engine.policies:
                if p.policy_id == policy_id:
                    policy = p
                    break
            
            if not policy:
                continue
            
            # Update based on recommendations
            if 'threshold_adjustment' in recommendations:
                # Adjust threat level threshold
                # This would require policy modification
                self.stats['threshold_adjustments'] += 1
                logger.debug(f"Adjusted threshold for policy {policy_id}")
    
    def _cleanup_outdated_policies(self) -> None:
        """Remove policies that are no longer relevant."""
        current_time = time.time()
        policies_to_remove = []
        
        for policy in self.decision_maker.policy_engine.policies:
            # Check if it's an adaptive policy
            if not policy.policy_id.startswith('adaptive_'):
                continue
            
            # Check if policy is outdated
            created_at = policy.parameters.get('created_at', 0)
            age_days = (current_time - created_at) / 86400
            
            # Remove policies older than 30 days with low success rate
            success_rate = policy.parameters.get('success_rate', 0.0)
            if age_days > 30 and success_rate < 0.3:
                policies_to_remove.append(policy.policy_id)
        
        for policy_id in policies_to_remove:
            self.decision_maker.policy_engine.remove_policy(policy_id)
            self.stats['policies_removed'] += 1
            logger.info(f"Removed outdated adaptive policy: {policy_id}")
    
    def adjust_thresholds(self,
                         pattern_type: str,
                         adjustment: float) -> None:
        """
        Adjust detection thresholds based on feedback.
        
        Args:
            pattern_type: Type of pattern
            adjustment: Adjustment value (-1 to 1)
        """
        # This would adjust thresholds in detection engines
        # For now, just log the adjustment
        logger.info(f"Adjusting threshold for {pattern_type} by {adjustment}")
        self.stats['threshold_adjustments'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get adaptive policy updater statistics."""
        return {
            **self.stats,
            'total_adaptive_policies': len([
                p for p in self.decision_maker.policy_engine.policies
                if p.policy_id.startswith('adaptive_')
            ]),
            'update_history_count': len(self.update_history)
        }

