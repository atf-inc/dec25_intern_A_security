"""
Reinforcement Learning Agent using Deep Q-Network (DQN)
Learns optimal actions for different attack patterns
"""

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from typing import Dict, Any, Optional, Tuple, List
import logging
from collections import deque
import random
from pathlib import Path
import json

from .state_encoder import StateEncoder
from .experience_buffer import ExperienceBuffer
from .reward_calculator import RewardCalculator
from ..core.decision_maker import ActionType, Decision, ThreatContext

logger = logging.getLogger(__name__)


class DQNNetwork(nn.Module):
    """Deep Q-Network architecture."""
    
    def __init__(self, state_size: int, action_size: int, hidden_sizes: List[int] = None):
        super(DQNNetwork, self).__init__()
        
        if hidden_sizes is None:
            hidden_sizes = [256, 128, 64]
        
        layers = []
        input_size = state_size
        
        for hidden_size in hidden_sizes:
            layers.append(nn.Linear(input_size, hidden_size))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(0.2))
            input_size = hidden_size
        
        layers.append(nn.Linear(input_size, action_size))
        
        self.network = nn.Sequential(*layers)
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Forward pass."""
        return self.network(state)


class RLAgent:
    """Reinforcement Learning Agent for adaptive attack pattern learning."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # State and action spaces
        self.state_encoder = StateEncoder(self.config.get('state_encoder', {}))
        self.state_size = self.state_encoder.get_state_size()
        self.action_size = len(ActionType)
        
        # Action mapping
        self.action_to_idx = {action: idx for idx, action in enumerate(ActionType)}
        self.idx_to_action = {idx: action for action, idx in self.action_to_idx.items()}
        
        # DQN hyperparameters
        self.lr = self.config.get('learning_rate', 0.001)
        self.gamma = self.config.get('gamma', 0.95)  # Discount factor
        self.epsilon = self.config.get('epsilon_start', 1.0)  # Exploration rate
        self.epsilon_min = self.config.get('epsilon_min', 0.01)
        self.epsilon_decay = self.config.get('epsilon_decay', 0.995)
        self.batch_size = self.config.get('batch_size', 64)
        self.update_target_freq = self.config.get('update_target_freq', 100)
        self.memory_size = self.config.get('memory_size', 100000)
        
        # Device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"RL Agent using device: {self.device}")
        
        # Neural networks
        self.q_network = DQNNetwork(self.state_size, self.action_size).to(self.device)
        self.target_network = DQNNetwork(self.state_size, self.action_size).to(self.device)
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=self.lr)
        
        # Copy weights to target network
        self.update_target_network()
        
        # Experience buffer
        self.memory = ExperienceBuffer({
            'max_size': self.memory_size,
            'prioritized': self.config.get('prioritized_replay', True)
        })
        
        # Reward calculator
        self.reward_calculator = RewardCalculator(self.config.get('reward', {}))
        
        # Training state
        self.training_step = 0
        self.episode_count = 0
        
        # Statistics
        self.stats = {
            'total_actions': 0,
            'exploration_actions': 0,
            'exploitation_actions': 0,
            'total_reward': 0.0,
            'avg_reward': 0.0,
            'loss_history': deque(maxlen=1000)
        }
    
    def select_action(self, 
                     state: np.ndarray,
                     context: ThreatContext,
                     training: bool = True) -> ActionType:
        """
        Select an action using epsilon-greedy policy.
        
        Args:
            state: Current state vector
            context: Threat context
            training: Whether in training mode
        
        Returns:
            Selected action
        """
        self.stats['total_actions'] += 1
        
        # Exploration vs exploitation
        if training and random.random() < self.epsilon:
            # Exploration: random action
            action_idx = random.randrange(self.action_size)
            self.stats['exploration_actions'] += 1
        else:
            # Exploitation: use Q-network
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                q_values = self.q_network(state_tensor)
                action_idx = q_values.argmax().item()
                self.stats['exploitation_actions'] += 1
        
        action = self.idx_to_action[action_idx]
        return action
    
    def remember(self,
                state: np.ndarray,
                action: ActionType,
                reward: float,
                next_state: Optional[np.ndarray],
                done: bool,
                metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store experience in replay buffer."""
        action_idx = self.action_to_idx[action]
        self.memory.add(state, action_idx, reward, next_state, done, metadata)
        
        self.stats['total_reward'] += reward
    
    def train_step(self) -> Optional[float]:
        """
        Perform one training step.
        
        Returns:
            Loss value if training occurred, None otherwise
        """
        if not self.memory.is_ready(self.batch_size):
            return None
        
        # Sample batch
        batch = self.memory.get_batch(self.batch_size)
        
        states = torch.FloatTensor(batch['states']).to(self.device)
        actions = torch.LongTensor(batch['actions']).to(self.device)
        rewards = torch.FloatTensor(batch['rewards']).to(self.device)
        next_states = torch.FloatTensor(batch['next_states']).to(self.device)
        dones = torch.FloatTensor(batch['dones']).to(self.device)
        
        # Current Q values
        current_q_values = self.q_network(states).gather(1, actions.unsqueeze(1))
        
        # Next Q values from target network
        with torch.no_grad():
            next_q_values = self.target_network(next_states).max(1)[0]
            target_q_values = rewards + (1 - dones) * self.gamma * next_q_values
        
        # Compute loss
        loss = nn.MSELoss()(current_q_values.squeeze(), target_q_values)
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), 1.0)
        self.optimizer.step()
        
        # Update statistics
        loss_value = loss.item()
        self.stats['loss_history'].append(loss_value)
        self.training_step += 1
        
        # Update target network periodically
        if self.training_step % self.update_target_freq == 0:
            self.update_target_network()
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        return loss_value
    
    def update_target_network(self) -> None:
        """Copy weights from Q-network to target network."""
        self.target_network.load_state_dict(self.q_network.state_dict())
        logger.debug("Updated target network")
    
    def learn_from_decision(self,
                          context: ThreatContext,
                          decision: Decision,
                          outcome: Optional[Dict[str, Any]] = None) -> None:
        """
        Learn from a decision and its outcome.
        
        Args:
            context: Threat context
            decision: Decision made
            outcome: Optional outcome feedback
        """
        # Encode state
        state = self.state_encoder.encode(context)
        
        # Calculate reward
        reward = self.reward_calculator.calculate_reward(decision, context, outcome)
        
        # For next state, we use a simplified approach
        # In practice, you'd track the actual next state
        next_state = None  # Will be updated when next decision is made
        done = False  # Episode continues
        
        # Store experience
        self.remember(
            state=state,
            action=decision.action,
            reward=reward,
            next_state=next_state,
            done=done,
            metadata={
                'decision_id': decision.decision_id,
                'threat_level': decision.threat_level.name,
                'confidence': decision.confidence.name
            }
        )
        
        # Train
        loss = self.train_step()
        
        if loss is not None:
            logger.debug(f"RL training step: loss={loss:.4f}, reward={reward:.2f}")
    
    def update_with_feedback(self,
                           decision_id: str,
                           feedback: Dict[str, Any]) -> None:
        """Update agent with delayed feedback."""
        self.reward_calculator.record_feedback(decision_id, feedback)
    
    def get_q_values(self, state: np.ndarray) -> Dict[ActionType, float]:
        """Get Q-values for all actions given a state."""
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            q_values = self.q_network(state_tensor).squeeze().cpu().numpy()
        
        return {self.idx_to_action[i]: float(q_values[i]) for i in range(self.action_size)}
    
    def save(self, filepath: Path) -> None:
        """Save agent to disk."""
        try:
            checkpoint = {
                'q_network_state_dict': self.q_network.state_dict(),
                'target_network_state_dict': self.target_network.state_dict(),
                'optimizer_state_dict': self.optimizer.state_dict(),
                'epsilon': self.epsilon,
                'training_step': self.training_step,
                'episode_count': self.episode_count,
                'stats': self.stats,
                'config': self.config
            }
            
            torch.save(checkpoint, filepath)
            
            # Save experience buffer separately
            buffer_path = filepath.parent / f"{filepath.stem}_buffer.pkl"
            self.memory.save(buffer_path)
            
            logger.info(f"Saved RL agent to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save RL agent: {e}")
    
    def load(self, filepath: Path) -> None:
        """Load agent from disk."""
        try:
            # Use weights_only=False for full checkpoint loading (includes optimizer, stats, etc.)
            checkpoint = torch.load(filepath, map_location=self.device, weights_only=False)
            
            self.q_network.load_state_dict(checkpoint['q_network_state_dict'])
            self.target_network.load_state_dict(checkpoint['target_network_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            self.epsilon = checkpoint.get('epsilon', self.epsilon)
            self.training_step = checkpoint.get('training_step', 0)
            self.episode_count = checkpoint.get('episode_count', 0)
            self.stats = checkpoint.get('stats', self.stats)
            
            # Load experience buffer
            buffer_path = filepath.parent / f"{filepath.stem}_buffer.pkl"
            if buffer_path.exists():
                self.memory.load(buffer_path)
            
            logger.info(f"Loaded RL agent from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load RL agent: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics."""
        exploration_rate = (
            self.stats['exploration_actions'] / max(1, self.stats['total_actions'])
        )
        
        avg_loss = (
            np.mean(self.stats['loss_history']) 
            if self.stats['loss_history'] else 0.0
        )
        
        return {
            **self.stats,
            'epsilon': self.epsilon,
            'exploration_rate': exploration_rate,
            'avg_loss': avg_loss,
            'memory_size': self.memory.size(),
            'training_step': self.training_step,
            'episode_count': self.episode_count
        }
    
    def set_training_mode(self, training: bool) -> None:
        """Set training or evaluation mode."""
        if training:
            self.q_network.train()
        else:
            self.q_network.eval()
            self.epsilon = 0.0  # No exploration in eval mode

