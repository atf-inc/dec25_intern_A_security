# QuantumShield - Quick Start

## 🚀 How to Run

### 1. Start the Complete Firewall

From the `quantumshield` directory:

```bash
python full_run.py
```

This starts:
- ✅ QuantumShield Engine
- ✅ Adaptive Learning Module
- ✅ REST API Server (port 8000)
- ✅ All Detection Engines

### 2. Start Vulnerable App (Optional)

In a separate terminal:

```bash
cd vulnerable-app
npm run dev  # or your app's start command
```

### 3. Test Adaptive Learning

In another terminal, from the `quantumshield` directory:

```bash
cd adaptive_learning
python test_adaptive_learning.py
```

This will:
- ✅ Test pattern learning with SQL injection, XSS, port scan attacks
- ✅ Test pattern recognition
- ✅ Test RL agent action suggestions
- ✅ Display statistics
- ✅ Verify integration (if vulnerable-app is running)

## 📋 Prerequisites

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Make sure you're in the correct directory:
```bash
cd quantumshield  # Should be here
```

## 🛠️ Troubleshooting

### Import Errors
If you get import errors, make sure you're running from the `quantumshield` directory:
```bash
cd C:\Users\Dell\Desktop\AITF_AI\quantumshield
python full_run.py
```

### Port Already in Use
If port 8000 is in use, modify `full_run.py` to change the API port in the `create_config()` function.

### Adaptive Learning Not Saving
Check that the `adaptive_learning` directory exists and is writable.

## 📊 What Gets Tested

The test script verifies:
1. **Pattern Learning** - Learns attack patterns from examples
2. **Pattern Recognition** - Recognizes similar attacks
3. **RL Suggestions** - Provides action recommendations
4. **Statistics** - Tracks learning progress
5. **Integration** - Works with running services

## 🎯 Expected Output

When running `full_run.py`, you should see:
```
============================================================
QuantumShield - Starting Full Firewall
============================================================
Initializing QuantumShield Engine...
Initializing Adaptive Learning module...
Adaptive learning integrated with engine
API server started on 0.0.0.0:8000
QuantumShield is running...
Press Ctrl+C to stop
```

When running `test_adaptive_learning.py`, you should see test results for each component.

