# QuantumShield Quick Start Guide

## Starting the Firewall

To start the complete QuantumShield firewall with adaptive learning:

```bash
python full_run.py
```

This will:
- Initialize the QuantumShield engine
- Enable adaptive learning module
- Start the REST API server (port 8000)
- Begin processing threats and learning patterns

## Testing Adaptive Learning

After starting the firewall and vulnerable-app, test the adaptive learning module:

```bash
cd adaptive_learning
python test_adaptive_learning.py
```

This test script will:
- Test pattern learning with various attacks (SQL injection, XSS, port scans)
- Test pattern recognition
- Test RL agent suggestions
- Collect and display statistics
- Verify integration with vulnerable-app (if running)

## Running with Vulnerable App

1. Start the vulnerable app in one terminal:
```bash
cd vulnerable-app
npm run dev  # or appropriate command
```

2. Start QuantumShield in another terminal:
```bash
python full_run.py
```

3. Run adaptive learning tests in a third terminal:
```bash
cd adaptive_learning
python test_adaptive_learning.py
```

## Configuration

The firewall configuration can be modified in `full_run.py` in the `create_config()` function.

Key settings:
- `capture.enabled`: Enable/disable packet capture
- `adaptive_learning.training_mode`: Enable training mode
- `adaptive_learning.learning_enabled`: Enable learning
- `api.enabled`: Enable REST API server

## Stopping

Press `Ctrl+C` to gracefully stop the firewall. The adaptive learning state will be saved automatically.

