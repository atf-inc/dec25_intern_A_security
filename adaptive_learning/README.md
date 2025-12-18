# Adaptive Learning Module

## Overview

The Adaptive Learning module implements a Reinforcement Learning (RL) based system that learns attack patterns and adapts firewall policies dynamically. It uses Deep Q-Network (DQN) to learn optimal responses to different attack scenarios.

## Features

- **Reinforcement Learning Agent**: Uses DQN to learn optimal actions for attack patterns
- **Pattern Learning**: Automatically learns and recognizes attack patterns
- **Adaptive Policies**: Dynamically creates and updates security policies based on learned patterns
- **State Encoding**: Converts threat context into numerical state vectors
- **Reward Calculation**: Calculates rewards based on attack prevention success
- **Experience Replay**: Stores and samples experiences for training

## Architecture

```
AdaptiveLearner (Main Integration)
├── RLAgent (DQN-based learning)
│   ├── StateEncoder (Context → State vectors)
│   ├── RewardCalculator (Outcome → Rewards)
│   └── ExperienceBuffer (Experience storage)
├── PatternLearner (Pattern recognition & storage)
└── AdaptivePolicyUpdater (Policy management)
```

## Components

### 1. RL Agent (`rl_agent.py`)

Deep Q-Network agent that learns optimal actions:
- **State Space**: 128-dimensional vectors encoding threat context
- **Action Space**: All available firewall actions (ALLOW, BLOCK, RATE_LIMIT, etc.)
- **Learning**: Uses experience replay and target network for stable learning

**Key Methods:**
- `select_action()`: Choose action using epsilon-greedy policy
- `learn_from_decision()`: Learn from decision outcomes
- `train_step()`: Perform one training step

### 2. State Encoder (`state_encoder.py`)

Converts threat context into numerical state vectors:
- Network features (IP, port, protocol)
- Threat indicators (types, severities, counts)
- Behavioral patterns (packet counts, rates, durations)
- Temporal features (time of day, day of week)
- ML model scores
- Reputation scores

### 3. Reward Calculator (`reward_calculator.py`)

Calculates rewards based on decision outcomes:
- **Positive Rewards**: Attack prevented, correct detection
- **Negative Rewards**: False positives, false negatives, missed attacks
- **Temporal Rewards**: Faster detection is better
- **Pattern Rewards**: Bonus for recognizing known patterns

### 4. Experience Buffer (`experience_buffer.py`)

Stores experiences for training:
- Supports prioritized experience replay
- Configurable buffer size
- Automatic cleanup of old experiences

### 5. Pattern Learner (`pattern_learner.py`)

Learns and stores attack patterns:
- Extracts features from threat contexts
- Calculates pattern similarity
- Stores patterns with confidence scores
- Recognizes similar patterns in new contexts

### 6. Adaptive Policy Updater (`adaptive_policy.py`)

Creates and updates policies based on learned patterns:
- Auto-generates policies for high-confidence patterns
- Updates existing policies based on success rates
- Removes outdated policies
- Adjusts detection thresholds

## Usage

### Basic Integration

```python
from quantumshield.adaptive_learning import AdaptiveLearner
from quantumshield.core.decision_maker import DecisionMaker

# Initialize
decision_maker = DecisionMaker(config)
adaptive_learner = AdaptiveLearner(decision_maker, config={
    'training_mode': True,
    'learning_enabled': True
})

# Initialize
await adaptive_learner.initialize()

# Process decisions
await adaptive_learner.process_decision(context, decision, outcome)

# Get action suggestions
suggestion = await adaptive_learner.suggest_action(context)
```

### Configuration

```python
config = {
    'rl_agent': {
        'learning_rate': 0.001,
        'gamma': 0.95,
        'epsilon_start': 1.0,
        'epsilon_min': 0.01,
        'epsilon_decay': 0.995,
        'batch_size': 64,
        'memory_size': 100000,
        'prioritized_replay': True
    },
    'pattern_learner': {
        'similarity_threshold': 0.7,
        'min_pattern_count': 3,
        'storage_path': 'patterns'
    },
    'policy_updater': {
        'min_confidence': 0.7,
        'min_pattern_count': 5,
        'update_interval': 3600
    },
    'storage_path': 'adaptive_learning'
}
```

## Learning Process

1. **Observation**: System observes threat context
2. **State Encoding**: Context is encoded into state vector
3. **Action Selection**: RL agent selects action (exploration or exploitation)
4. **Decision Execution**: Action is executed
5. **Reward Calculation**: Reward is calculated based on outcome
6. **Pattern Learning**: Pattern is learned or updated
7. **Policy Update**: Policies are updated based on learned patterns
8. **Experience Storage**: Experience is stored for training

## Training Modes

### Training Mode (Default)
- Explores different actions (epsilon-greedy)
- Learns from all decisions
- Updates patterns and policies
- Stores experiences for training

### Evaluation Mode
- Uses learned policy (no exploration)
- Only recognizes patterns
- Does not update models
- Useful for production deployment

## Statistics

Get comprehensive statistics:

```python
stats = adaptive_learner.get_statistics()
# Returns:
# - Decisions processed
# - Patterns recognized/learned
# - Policies updated
# - RL agent statistics
# - Pattern learner statistics
# - Policy updater statistics
```

## Saving and Loading

```python
# Save state
await adaptive_learner.save_state()

# State is automatically loaded on initialization
await adaptive_learner.initialize()
```

## Integration with Engine

The adaptive learner integrates with the main QuantumShield engine:

```python
# In engine.py
from quantumshield.adaptive_learning import AdaptiveLearner

class QuantumShieldEngine:
    def __init__(self, config):
        # ... existing code ...
        self.adaptive_learner = AdaptiveLearner(
            self.decision_maker,
            config.get('adaptive_learning', {})
        )
    
    async def _decision_loop(self):
        # ... existing decision logic ...
        
        # Get RL suggestion (optional)
        suggestion = await self.adaptive_learner.suggest_action(context)
        
        # Make decision (can incorporate suggestion)
        decision = await self.decision_maker.make_decision(context, indicators)
        
        # Learn from decision
        await self.adaptive_learner.process_decision(context, decision, outcome)
```

## Performance Considerations

- **State Encoding**: Optimized for fast feature extraction
- **RL Training**: Runs asynchronously, doesn't block decision making
- **Pattern Matching**: Uses efficient similarity calculations
- **Policy Updates**: Batched and periodic to avoid overhead

## Future Enhancements

- Multi-agent RL for distributed learning
- Transfer learning from other environments
- Online learning with concept drift detection
- Explainable AI for policy decisions
- Federated learning across multiple deployments

## Requirements

- PyTorch (for DQN)
- NumPy
- Standard QuantumShield dependencies

## References

- Deep Q-Network (DQN): Mnih et al., 2015
- Prioritized Experience Replay: Schaul et al., 2016
- Adaptive Security: Continuous learning from feedback

