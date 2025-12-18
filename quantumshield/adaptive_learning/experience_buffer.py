"""
Experience Replay Buffer for Reinforcement Learning
Stores and samples experiences for training the RL agent
"""

import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from collections import deque
import random
import logging
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)


class Experience:
    """Represents a single experience tuple (state, action, reward, next_state, done)."""
    
    def __init__(self,
                 state: np.ndarray,
                 action: int,
                 reward: float,
                 next_state: Optional[np.ndarray],
                 done: bool,
                 metadata: Optional[Dict[str, Any]] = None):
        self.state = state
        self.action = action
        self.reward = reward
        self.next_state = next_state
        self.done = done
        self.metadata = metadata or {}
    
    def to_tuple(self) -> Tuple:
        """Convert to tuple format."""
        return (self.state, self.action, self.reward, self.next_state, self.done)


class ExperienceBuffer:
    """Experience replay buffer for storing and sampling experiences."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_size = self.config.get('max_size', 100000)
        self.buffer: deque = deque(maxlen=self.max_size)
        
        # Prioritized experience replay settings
        self.prioritized = self.config.get('prioritized', False)
        self.alpha = self.config.get('alpha', 0.6)  # Priority exponent
        self.beta = self.config.get('beta', 0.4)  # Importance sampling exponent
        self.beta_increment = self.config.get('beta_increment', 0.001)
        self.max_priority = 1.0
        
        if self.prioritized:
            self.priorities: deque = deque(maxlen=self.max_size)
            self.max_priority = 1.0
        
        # Statistics
        self.stats = {
            'total_added': 0,
            'total_sampled': 0,
            'high_reward_count': 0,
            'low_reward_count': 0
        }
    
    def add(self,
           state: np.ndarray,
           action: int,
           reward: float,
           next_state: Optional[np.ndarray],
           done: bool,
           metadata: Optional[Dict[str, Any]] = None,
           priority: Optional[float] = None) -> None:
        """
        Add an experience to the buffer.
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state (None if done)
            done: Whether episode is done
            metadata: Optional metadata
            priority: Optional priority (for prioritized replay)
        """
        experience = Experience(state, action, reward, next_state, done, metadata)
        self.buffer.append(experience)
        
        if self.prioritized:
            if priority is None:
                # Use absolute TD error as priority
                priority = abs(reward) + 0.1
            self.priorities.append(priority)
            self.max_priority = max(self.max_priority, priority)
        
        # Update statistics
        self.stats['total_added'] += 1
        if reward > 5.0:
            self.stats['high_reward_count'] += 1
        elif reward < -5.0:
            self.stats['low_reward_count'] += 1
    
    def sample(self, batch_size: int) -> Tuple[List[Experience], Optional[np.ndarray]]:
        """
        Sample a batch of experiences.
        
        Args:
            batch_size: Number of experiences to sample
            
        Returns:
            Tuple of (experiences, importance_weights)
        """
        if len(self.buffer) < batch_size:
            batch_size = len(self.buffer)
        
        if self.prioritized:
            return self._prioritized_sample(batch_size)
        else:
            experiences = random.sample(self.buffer, batch_size)
            return experiences, None
    
    def _prioritized_sample(self, batch_size: int) -> Tuple[List[Experience], np.ndarray]:
        """Sample using prioritized experience replay."""
        # Calculate sampling probabilities
        priorities = np.array(list(self.priorities))
        probabilities = priorities ** self.alpha
        probabilities /= probabilities.sum()
        
        # Sample indices
        indices = np.random.choice(len(self.buffer), batch_size, p=probabilities)
        experiences = [self.buffer[i] for i in indices]
        
        # Calculate importance sampling weights
        weights = (len(self.buffer) * probabilities[indices]) ** (-self.beta)
        weights /= weights.max()  # Normalize
        
        # Update beta
        self.beta = min(1.0, self.beta + self.beta_increment)
        
        return experiences, weights
    
    def update_priorities(self, indices: List[int], td_errors: np.ndarray) -> None:
        """Update priorities based on TD errors (for prioritized replay)."""
        if not self.prioritized:
            return
        
        for idx, td_error in zip(indices, td_errors):
            if 0 <= idx < len(self.priorities):
                priority = (abs(td_error) + 1e-6) ** self.alpha
                self.priorities[idx] = priority
                self.max_priority = max(self.max_priority, priority)
    
    def get_batch(self, batch_size: int) -> Dict[str, np.ndarray]:
        """
        Get a batch of experiences in a format suitable for training.
        
        Returns:
            Dictionary with keys: states, actions, rewards, next_states, dones
        """
        experiences, weights = self.sample(batch_size)
        
        batch = {
            'states': np.array([exp.state for exp in experiences]),
            'actions': np.array([exp.action for exp in experiences]),
            'rewards': np.array([exp.reward for exp in experiences]),
            'next_states': np.array([
                exp.next_state if exp.next_state is not None else exp.state
                for exp in experiences
            ]),
            'dones': np.array([exp.done for exp in experiences], dtype=np.float32)
        }
        
        if weights is not None:
            batch['weights'] = weights
        
        return batch
    
    def size(self) -> int:
        """Get current buffer size."""
        return len(self.buffer)
    
    def is_ready(self, min_size: int = 1000) -> bool:
        """Check if buffer has enough experiences for training."""
        return len(self.buffer) >= min_size
    
    def clear(self) -> None:
        """Clear the buffer."""
        self.buffer.clear()
        if self.prioritized:
            self.priorities.clear()
        self.stats = {
            'total_added': 0,
            'total_sampled': 0,
            'high_reward_count': 0,
            'low_reward_count': 0
        }
    
    def save(self, filepath: Path) -> None:
        """Save buffer to disk."""
        try:
            data = {
                'buffer': list(self.buffer),
                'priorities': list(self.priorities) if self.prioritized else None,
                'stats': self.stats,
                'config': self.config
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(data, f)
            
            logger.info(f"Saved experience buffer to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save experience buffer: {e}")
    
    def load(self, filepath: Path) -> None:
        """Load buffer from disk."""
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
            
            self.buffer = deque(data['buffer'], maxlen=self.max_size)
            if self.prioritized and data['priorities']:
                self.priorities = deque(data['priorities'], maxlen=self.max_size)
            self.stats = data.get('stats', self.stats)
            
            logger.info(f"Loaded experience buffer from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load experience buffer: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        if not self.buffer:
            return self.stats
        
        rewards = [exp.reward for exp in self.buffer]
        
        return {
            **self.stats,
            'current_size': len(self.buffer),
            'max_size': self.max_size,
            'utilization': len(self.buffer) / self.max_size,
            'avg_reward': np.mean(rewards),
            'min_reward': np.min(rewards),
            'max_reward': np.max(rewards),
            'std_reward': np.std(rewards)
        }

