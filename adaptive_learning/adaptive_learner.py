"""
Main Adaptive Learning Module
Integrates RL agent, pattern learner, and policy updater
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import time

from .rl_agent import RLAgent
from .pattern_learner import PatternLearner
from .adaptive_policy import AdaptivePolicyUpdater
from .state_encoder import StateEncoder
from ..core.decision_maker import DecisionMaker, Decision, ThreatContext

logger = logging.getLogger(__name__)


class AdaptiveLearner:
    """
    Main adaptive learning system that integrates RL, pattern learning, and policy updates.
    """
    
    def __init__(self,
                 decision_maker: DecisionMaker,
                 config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.decision_maker = decision_maker
        
        # Initialize components
        self.rl_agent = RLAgent(self.config.get('rl_agent', {}))
        self.pattern_learner = PatternLearner(self.config.get('pattern_learner', {}))
        self.policy_updater = AdaptivePolicyUpdater(
            decision_maker,
            self.config.get('policy_updater', {})
        )
        
        # Training mode
        self.training_mode = self.config.get('training_mode', True)
        self.learning_enabled = self.config.get('learning_enabled', True)
        
        # Storage paths
        self.storage_path = Path(self.config.get('storage_path', 'adaptive_learning'))
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.stats = {
            'decisions_processed': 0,
            'patterns_recognized': 0,
            'patterns_learned': 0,
            'policies_updated': 0
        }
        
        logger.info("AdaptiveLearner initialized")
    
    async def initialize(self) -> None:
        """Initialize the adaptive learner."""
        logger.info("Initializing adaptive learner...")
        
        # Load saved models and patterns
        await self._load_saved_state()
        
        logger.info("Adaptive learner initialized")
    
    async def process_decision(self,
                             context: ThreatContext,
                             decision: Decision,
                             outcome: Optional[Dict[str, Any]] = None) -> None:
        """
        Process a decision for learning.
        
        Args:
            context: Threat context
            decision: Decision made
            outcome: Optional outcome feedback
        """
        if not self.learning_enabled:
            return
        
        self.stats['decisions_processed'] += 1
        
        # Check for known patterns
        recognized_pattern = self.pattern_learner.recognize_pattern(context)
        
        if recognized_pattern:
            self.stats['patterns_recognized'] += 1
            logger.debug(f"Recognized pattern: {recognized_pattern['pattern_id']}")
        
        # Learn pattern
        if self.training_mode:
            pattern_id = self.pattern_learner.learn_pattern(context, decision, outcome)
            if pattern_id:
                self.stats['patterns_learned'] += 1
        
        # RL learning
        if self.training_mode:
            self.rl_agent.learn_from_decision(context, decision, outcome)
        
        # Periodic policy updates
        if self.stats['decisions_processed'] % 100 == 0:
            await self._update_policies()
    
    async def suggest_action(self,
                            context: ThreatContext) -> Optional[Dict[str, Any]]:
        """
        Suggest an action using RL agent.
        
        Args:
            context: Threat context
            
        Returns:
            Dictionary with suggested action and confidence
        """
        if not self.learning_enabled:
            return None
        
        # Encode state
        state = self.rl_agent.state_encoder.encode(context)
        
        # Get Q-values
        q_values = self.rl_agent.get_q_values(state)
        
        # Get best action
        best_action = max(q_values.items(), key=lambda x: x[1])
        
        # Check for recognized pattern
        recognized_pattern = self.pattern_learner.recognize_pattern(context)
        
        suggestion = {
            'action': best_action[0],
            'q_value': best_action[1],
            'confidence': min(1.0, abs(best_action[1]) / 10.0),  # Normalize
            'all_q_values': q_values
        }
        
        if recognized_pattern:
            suggestion['pattern_id'] = recognized_pattern['pattern_id']
            suggestion['pattern_confidence'] = recognized_pattern['confidence']
            suggestion['pattern_recommended_action'] = recognized_pattern.get('recommended_action')
        
        return suggestion
    
    async def update_with_feedback(self,
                                  decision_id: str,
                                  feedback: Dict[str, Any]) -> None:
        """Update learning with delayed feedback."""
        if not self.learning_enabled:
            return
        
        # Update RL agent
        self.rl_agent.update_with_feedback(decision_id, feedback)
        
        # Update pattern learner if needed
        # (Patterns are updated when new decisions are processed)
    
    async def _update_policies(self) -> None:
        """Update policies based on learned patterns."""
        # Get all patterns
        patterns = {
            pattern_id: pattern.to_dict()
            for pattern_id, pattern in self.pattern_learner.patterns.items()
        }
        
        # Update policies
        self.policy_updater.update_policies_from_patterns(patterns)
        self.stats['policies_updated'] += 1
    
    async def _load_saved_state(self) -> None:
        """Load saved RL agent and patterns."""
        try:
            # Load RL agent
            rl_path = self.storage_path / 'rl_agent.pt'
            if rl_path.exists():
                self.rl_agent.load(rl_path)
                logger.info("Loaded RL agent from disk")
            
            # Load patterns
            self.pattern_learner.load_patterns()
            logger.info("Loaded patterns from disk")
        except Exception as e:
            logger.error(f"Failed to load saved state: {e}")
    
    async def save_state(self) -> None:
        """Save current state to disk."""
        try:
            # Save RL agent
            rl_path = self.storage_path / 'rl_agent.pt'
            self.rl_agent.save(rl_path)
            
            # Save patterns
            self.pattern_learner.save_patterns()
            
            logger.info("Saved adaptive learner state")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        return {
            **self.stats,
            'rl_agent': self.rl_agent.get_statistics(),
            'pattern_learner': self.pattern_learner.get_statistics(),
            'policy_updater': self.policy_updater.get_statistics(),
            'training_mode': self.training_mode,
            'learning_enabled': self.learning_enabled
        }
    
    def set_training_mode(self, enabled: bool) -> None:
        """Enable or disable training mode."""
        self.training_mode = enabled
        self.rl_agent.set_training_mode(enabled)
        logger.info(f"Training mode: {enabled}")
    
    def set_learning_enabled(self, enabled: bool) -> None:
        """Enable or disable learning."""
        self.learning_enabled = enabled
        logger.info(f"Learning enabled: {enabled}")
    
    async def shutdown(self) -> None:
        """Shutdown and save state."""
        logger.info("Shutting down adaptive learner...")
        await self.save_state()
        logger.info("Adaptive learner shut down")

