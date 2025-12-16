# QuantumShield Firewall - Setup and Run Guide

## 📋 Overview

This guide will help you set up and run the QuantumShield Firewall with the vulnerable-app for testing all firewall functions (except integration section).

## 🏗️ Project Architecture

### Core Components

1. **QuantumShield Engine** (`quantumshield/core/engine.py`)
   - Main orchestration engine
   - Coordinates all system components
   - Manages packet capture, processing, analysis, and response

2. **Packet Capture** (`quantumshield/core/packet_capture.py`)
   - Captures network packets (simulated for testing)
   - Queues packets for processing

3. **Traffic Processor** (`quantumshield/core/traffic_processor.py`)
   - Processes raw packets into flow data
   - Tracks network flows

4. **Decision Maker** (`quantumshield/core/decision_maker.py`)
   - Analyzes threat indicators
   - Makes blocking/allowing decisions

5. **Response Executor** (`quantumshield/core/response_executor.py`)
   - Executes actions (block, log, allow)
   - Manages IP blocking

### Detection Engines

1. **Signature Engine** (`quantumshield/detection_engines/signature_engine.py`)
   - Pattern-based detection
   - Known attack signatures

2. **Anomaly Engine** (`quantumshield/detection_engines/anomaly_engine.py`)
   - Statistical anomaly detection
   - Behavioral analysis

3. **Behavioral Engine** (`quantumshield/detection_engines/behavioral_engine.py`)
   - User behavior analysis
   - Session tracking

### Application Layer (L7)

1. **WAF Engine** (`quantumshield/application_layer/waf/waf_engine.py`)
   - OWASP CRS rules engine
   - SQL injection detection
   - XSS detection
   - Command injection detection
   - Path traversal detection
   - SSRF detection
   - Bot detection
   - GeoIP filtering
   - IP access control

2. **HTTP Inspector** (`quantumshield/application_layer/http_inspector.py`)
   - HTTP/HTTPS traffic parsing
   - Header analysis
   - Body analysis
   - URI analysis

### Network Layer (L3/L4)

1. **DDoS Detector** (`quantumshield/network_layer/ddos_detector.py`)
   - ML-based DDoS detection
   - Rate limiting
   - Flood detection

### Additional Components

1. **QuantumLLMA Manager** (`quantumshield/quantum_llma/manager.py`)
   - GenAI security scanning
   - Prompt injection detection

2. **Reverse Proxy** (`quantumshield/proxy/reverse_proxy.py`)
   - Intercepts HTTP traffic
   - Forwards to backend after analysis
   - Blocks malicious requests

## 🚀 Quick Start

### Step 1: Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# If you get errors, install PyYAML separately
pip install pyyaml
```

### Step 2: Set Up Vulnerable App

```bash
# Navigate to vulnerable app directory
cd quantumshield/vulnerable-app/vulnerable-app

# Install Node.js dependencies
npm install

# Create .env.local file (optional - for WAF testing)
# Copy .env.example to .env.local if needed
```

### Step 3: Start Vulnerable App

```bash
# In quantumshield/vulnerable-app/vulnerable-app directory
npm run dev
```

The vulnerable app will run on `http://localhost:3000`

### Step 4: Start QuantumShield Firewall

```bash
# From the AITF_IPS root directory
python full_run.py
```

The firewall will:
- Start the engine
- Start the reverse proxy on `http://localhost:8080`
- Forward traffic to `http://localhost:3000` (vulnerable app)
- Protect all traffic going through port 8080

### Step 5: Test the Firewall

```bash
# In a new terminal, run the test script
python test_firewall.py
```

## 📝 Configuration

The firewall uses `config.yaml` for configuration. Key settings:

```yaml
# WAF Configuration
waf:
  enabled: true
  block_on_violation: true

# Detection Engines
detection_engines:
  signature:
    enabled: true
  anomaly:
    enabled: true
  behavioral:
    enabled: true

# Integrations (DISABLED)
integrations:
  enabled: false

# Proxy Configuration
proxy:
  enabled: true
  port: 8080
  backend_url: "http://localhost:3000"
```

## 🧪 Testing

### Manual Testing

1. **Access the protected app**: `http://localhost:8080`
2. **Try SQL Injection**: `http://localhost:8080/search?q=test' OR '1'='1`
   - Should be blocked (403 Forbidden)
3. **Try XSS**: `http://localhost:8080/search?q=<script>alert('XSS')</script>`
   - Should be blocked (403 Forbidden)
4. **Try legitimate traffic**: `http://localhost:8080/products`
   - Should be allowed (200 OK)

### Automated Testing

```bash
python test_firewall.py
```

The test script will:
- Test connection to firewall
- Test WAF SQL injection detection
- Test WAF XSS detection
- Test WAF command injection detection
- Test WAF path traversal detection
- Test WAF SSRF detection
- Test legitimate traffic (should be allowed)
- Test DDoS detection
- Test engine components

## 🔍 Functionality Overview

### What's Working

✅ **WAF Engine**
- SQL injection detection
- XSS detection
- Command injection detection
- Path traversal detection
- SSRF detection
- Bot detection
- IP access control
- OWASP CRS rules

✅ **Detection Engines**
- Signature-based detection
- Anomaly detection
- Behavioral detection

✅ **Network Layer**
- DDoS detection (ML-based)
- Rate limiting

✅ **Reverse Proxy**
- Traffic interception
- Request analysis
- Response forwarding

✅ **PurpleLlama** (if available)
- GenAI security scanning

### What's Disabled

❌ **Integrations Section** (as requested)
- External tool integrations (Nmap, Snort, etc.)
- Set `integrations.enabled: false` in config

## 📊 Monitoring

### Logs

- **Application logs**: `quantumshield_run.log`
- **WAF reports**: `logs/waf_reports/` (if configured)

### Statistics

The engine logs statistics every 60 seconds:
- Packets processed
- Threats detected
- Actions taken
- Queue sizes

## 🐛 Troubleshooting

### Issue: Cannot connect to firewall

**Solution**: Make sure the firewall is running:
```bash
python full_run.py
```

### Issue: Vulnerable app not accessible

**Solution**: Make sure the vulnerable app is running on port 3000:
```bash
cd quantumshield/vulnerable-app/vulnerable-app
npm run dev
```

### Issue: Import errors

**Solution**: Install all dependencies:
```bash
pip install -r requirements.txt
```

### Issue: WAF not blocking attacks

**Solution**: Check that WAF is enabled in `config.yaml`:
```yaml
waf:
  enabled: true
  block_on_violation: true
```

### Issue: Port already in use

**Solution**: Change the port in `config.yaml`:
```yaml
proxy:
  port: 8081  # Change to available port
```

## 📚 File Structure

```
AITF_IPS/
├── config.yaml              # Configuration file
├── full_run.py              # Main run script
├── test_firewall.py          # Test script
├── requirements.txt          # Python dependencies
├── quantumshield/
│   ├── core/                 # Core engine components
│   ├── detection_engines/    # Detection logic
│   ├── application_layer/    # WAF and L7 protection
│   ├── network_layer/        # L3/L4 protection
│   ├── proxy/                # Reverse proxy
│   └── vulnerable-app/       # Vulnerable app for testing
└── SETUP_AND_RUN.md          # This file
```

## 🎯 Next Steps

1. **Start the vulnerable app**: `npm run dev` (in vulnerable-app directory)
2. **Start the firewall**: `python full_run.py`
3. **Run tests**: `python test_firewall.py`
4. **Access protected app**: `http://localhost:8080`
5. **Try attacks**: See test script for examples

## ⚠️ Important Notes

- The firewall runs as a reverse proxy on port 8080
- All traffic to port 8080 is analyzed before forwarding to port 3000
- The vulnerable app should run on port 3000
- Integration section is disabled (external tools)
- Packet capture is simulated (not using raw sockets)

## 📞 Support

For issues or questions:
1. Check logs: `quantumshield_run.log`
2. Review configuration: `config.yaml`
3. Run test script: `python test_firewall.py`
