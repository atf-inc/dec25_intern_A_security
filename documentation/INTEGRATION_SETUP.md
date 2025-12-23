# QuantumShield Integration Setup Guide

This guide walks you through setting up all integrations for the QuantumShield Security System, including Slack notifications, email alerts, and the AI chatbot.

## Table of Contents
- [Slack Integration Setup](#slack-integration-setup)
- [Email Alert Setup (SendGrid)](#email-alert-setup-sendgrid)
- [AI Chatbot Setup (LLM Integration)](#ai-chatbot-setup-llm-integration)
- [Testing Integrations](#testing-integrations)
- [Troubleshooting](#troubleshooting)

---

## Slack Integration Setup

### Prerequisites
- A Slack workspace (create one at [slack.com](https://slack.com))
- Admin permissions to install apps

### Step 1: Create a Slack App

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps)
2. Click **"Create New App"**
3. Choose **"From scratch"**
4. Name your app: `QuantumShield Security`
5. Select your workspace
6. Click **"Create App"**

### Step 2: Enable Incoming Webhooks

1. In your app settings, click **"Incoming Webhooks"** in the left sidebar
2. Toggle **"Activate Incoming Webhooks"** to ON
3. Click **"Add New Webhook to Workspace"**
4. Select the channel where you want alerts (e.g., `#security-alerts`)
5. Click **"Allow"**
6. Copy the **Webhook URL** from Slack (it will start with `https://hooks.slack.com/services/...`)

### Step 3: Configure QuantumShield

1. Open your `.env` file in the `honeypot/` directory
2. Add the following configuration:

```bash
ENABLE_SLACK_ALERTS=true
SLACK_WEBHOOK_URL=<your-slack-webhook-url>
SLACK_CHANNEL=#security-alerts
```

3. Save the file

### Step 4: Customize Slack App (Optional)

1. In your Slack app settings, go to **"Basic Information"**
2. Upload an app icon (use a shield or security-related icon)
3. Set display information:
   - **App name**: QuantumShield Security
   - **Short description**: Real-time security threat monitoring
   - **Background color**: `#FF6B6B` (red for alerts)

### Slack Alert Types

QuantumShield sends three types of Slack alerts:

#### 1. **Real-time Attack Alerts**
Triggered for each MALICIOUS attack detected with confidence ≥ 80%

```python
# Automatically triggered by the honeypot
slack_notifier.send_attack_alert(
    ip="192.168.1.100",
    method="POST",
    path="/api/login",
    ml_verdict="MALICIOUS",
    ml_confidence=0.95,
    payload="' OR '1'='1",
    attack_type="SQL Injection"
)
```

**Example Slack Message:**
```
🔴 MALICIOUS Attack Detected
━━━━━━━━━━━━━━━━━━━━━━━━
Attack Type: SQL Injection
Source IP: 192.168.1.100
HTTP Method: POST
Confidence: 95.0%
Request Path: /api/login
Timestamp: 2025-12-23 14:30:00 UTC

Payload Preview:
' OR '1'='1
━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ QuantumShield Honeypot System | View Dashboard
```

#### 2. **Summary Alerts**
Periodic summaries of attack activity (configurable)

```python
# Can be scheduled via cron or triggered manually
slack_notifier.send_summary_alert(
    total_attacks=145,
    malicious_count=23,
    top_attackers=[("192.168.1.100", 15), ("10.0.0.50", 8)],
    attack_types={"SQL Injection": 12, "XSS": 8, "RCE": 3},
    time_period="Last Hour"
)
```

#### 3. **Critical Threat Alerts**
High-priority alerts that mention `@channel` for immediate attention

```python
# Triggered for repeated attacks or high-severity threats
slack_notifier.send_critical_threat_alert(
    ip="192.168.1.100",
    attack_count=25,
    threat_description="Multiple SQL injection attempts with database enumeration patterns",
    recommended_action="Block IP address and review database logs"
)
```

---

## Email Alert Setup (SendGrid)

### Prerequisites
- A SendGrid account ([signup here](https://signup.sendgrid.com/))
- Verified sender email address

### Step 1: Create SendGrid API Key

1. Log in to [SendGrid](https://app.sendgrid.com/)
2. Go to **Settings** → **API Keys**
3. Click **"Create API Key"**
4. Name it: `QuantumShield Alerts`
5. Select **"Full Access"** permission
6. Click **"Create & View"**
7. **Copy the API key** (you won't see it again!)

### Step 2: Verify Sender Email

1. Go to **Settings** → **Sender Authentication**
2. Click **"Single Sender Verification"**
3. Enter your email details:
   - From Name: `QuantumShield Alerts`
   - From Email Address: `alerts@yourdomain.com`
   - Reply To: `security@yourdomain.com`
4. Check your email and click the verification link

### Step 3: Configure QuantumShield

1. Open your `.env` file in the `honeypot/` directory
2. Add the following configuration:

```bash
ENABLE_EMAIL_ALERTS=true
SENDGRID_API_KEY=SG.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ALERT_FROM_EMAIL=alerts@yourdomain.com
ALERT_TO_EMAIL=security@yourdomain.com
```

3. Save the file

### Email Alert Features

- **HTML Formatted**: Professional, styled email templates
- **Attack Details**: IP, method, path, payload preview
- **Confidence Scores**: ML confidence percentage
- **Attack Classification**: Automatic attack type detection
- **One-Click Dashboard**: Direct link to security dashboard

### Example Email Alert

**Subject:** 🚨 MALICIOUS Attack Detected - SQL Injection from 192.168.1.100

**Body:**
```html
┌─────────────────────────────────┐
│  🚨 MALICIOUS Attack Detected   │
│    QuantumShield Security Alert │
└─────────────────────────────────┘

Alert Time: 2025-12-23 14:30:00 UTC
Attack Type: SQL Injection
Source IP: 192.168.1.100
HTTP Method: POST
Request Path: /api/login
ML Verdict: MALICIOUS
Confidence Score: 95%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Payload Preview:
' OR '1'='1 -- admin
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This is an automated alert from QuantumShield Honeypot System.
View full details in your security dashboard.
```

---

## AI Chatbot Setup (LLM Integration)

The QuantumShield chatbot uses LLM APIs (OpenAI or Anthropic) for natural language processing and forensics analysis.

### Prerequisites
- API key from OpenAI or Anthropic/Groq

### Option 1: OpenAI (GPT-4)

1. Create an account at [OpenAI](https://platform.openai.com/)
2. Go to **API Keys** section
3. Create a new API key
4. Add to `.env`:

```bash
GROQ_API_KEY=sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXX
LLM_MODEL=openai/gpt-4
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=100000
```

### Option 2: Groq (Fast Inference)

1. Sign up at [Groq](https://console.groq.com/)
2. Generate an API key
3. Add to `.env`:

```bash
GROQ_API_KEY=gsk_XXXXXXXXXXXXXXXXXXXXXXXXXXXX
LLM_MODEL=llama-3.1-70b-versatile
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=100000
```

### Chatbot Features

#### 1. **Natural Language Queries**
Ask questions in plain English:
- "Show me all SQL injection attempts in the last hour"
- "What are the top 10 attacking IPs?"
- "How many attacks happened today?"
- "Show attack distribution by type"

The chatbot translates these to MongoDB queries automatically.

#### 2. **Forensics Analysis**
Click on any session ID to get AI-powered analysis:
- **Attack Timeline**: Step-by-step breakdown of attacker actions
- **Intent Detection**: What the attacker was trying to achieve
- **Threat Level**: Low, Medium, High, or Critical
- **MITRE ATT&CK Mapping**: Techniques used (e.g., T1190 - Exploit Public-Facing Application)
- **Blocked Actions**: What the honeypot prevented

#### 3. **Interactive Visualizations**
The chatbot automatically generates:
- **Tables**: For listing attack records
- **Bar Charts**: For comparing attack counts
- **Pie Charts**: For attack distribution
- **Line Charts**: For time-series analysis

### Example Chatbot Interactions

**Query 1:**
```
User: Show me all SQL injections from the last 24 hours
Bot: Found 23 result(s). Here are SQL injection attempts from the last 24 hours.
[Displays interactive table with IP, timestamp, payload, confidence]
```

**Query 2:**
```
User: What are the top 5 attacking IPs?
Bot: Found 5 result(s). Top attacking IP addresses by request count.
[Displays bar chart with IP addresses and attack counts]
```

**Query 3:**
```
User: [Clicks on session ID: abc123def456]
Bot: Session analysis complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Forensics Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Session ID: abc123def456
IP Address: 192.168.1.100
Started: 2025-12-23 14:25:00 UTC

ANALYSIS:
The attacker began with reconnaissance by probing the /api/products 
endpoint with malformed input. After receiving a database error message,
they escalated to SQL injection attempts using UNION-based techniques...

INTENT: Data Exfiltration
The attacker's goal was to extract sensitive data from the database,
specifically targeting user credentials and product information.

THREAT LEVEL: HIGH
This is a sophisticated attack using advanced SQL injection techniques.

MITRE ATT&CK TECHNIQUES:
- T1190: Exploit Public-Facing Application
- T1213: Data from Information Repositories

BLOCKED ACTIONS:
✓ Database query manipulation
✓ File system access attempts
✓ Command execution attempts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Testing Integrations

### Test Slack Integration

Run the test script:

```bash
cd honeypot
python test_slack.py
```

Or manually trigger from Python:

```python
from core.slack_notifier import slack_notifier
import asyncio

asyncio.run(slack_notifier.send_attack_alert(
    ip="192.168.1.100",
    method="POST",
    path="/test",
    ml_verdict="MALICIOUS",
    ml_confidence=0.95,
    payload="' OR '1'='1",
    attack_type="SQL Injection (Test)"
))
```

### Test Email Integration

```bash
cd honeypot
python test_email.py
```

Or manually:

```python
from core.email_notifier import email_notifier
import asyncio

asyncio.run(email_notifier.send_attack_alert(
    ip="192.168.1.100",
    method="POST",
    path="/test",
    ml_verdict="MALICIOUS",
    ml_confidence=0.95,
    payload="' OR '1'='1"
))
```

### Test Chatbot

1. Start the honeypot: `uvicorn main:app --reload --port 8080`
2. Start the frontend: `cd frontend && npm run dev`
3. Open dashboard: `http://localhost:3001`
4. Click the chatbot button (bottom right)
5. Try these queries:
   - "Show me all attacks"
   - "What are the top attacking IPs?"
   - Click on any session ID

---

## Troubleshooting

### Slack Alerts Not Sending

**Problem**: No messages appearing in Slack

**Solutions**:
1. Check `.env` has `ENABLE_SLACK_ALERTS=true`
2. Verify webhook URL is correct (no extra spaces)
3. Check logs: `tail -f honeypot/error.log`
4. Test webhook manually:
   ```bash
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"Test message"}' \
     YOUR_WEBHOOK_URL
   ```
5. Ensure the Slack app is installed in your workspace
6. Check that the channel exists and the app has permissions

### Email Alerts Not Sending

**Problem**: No emails received

**Solutions**:
1. Verify `.env` has `ENABLE_EMAIL_ALERTS=true`
2. Check SendGrid API key is correct
3. Confirm sender email is verified in SendGrid
4. Check spam/junk folder
5. Review SendGrid activity log: [SendGrid Dashboard](https://app.sendgrid.com/email_activity)
6. Check logs for errors: `tail -f honeypot/error.log`
7. Test SendGrid directly:
   ```bash
   curl -X POST https://api.sendgrid.com/v3/mail/send \
     -H "Authorization: Bearer $SENDGRID_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"personalizations":[{"to":[{"email":"your@email.com"}]}],
          "from":{"email":"alerts@yourdomain.com"},
          "subject":"Test","content":[{"type":"text/plain","value":"Test"}]}'
   ```

### Chatbot Not Responding

**Problem**: Chatbot shows error or no response

**Solutions**:
1. Check LLM API key in `.env` file
2. Verify API key has not expired
3. Check API usage limits (OpenAI/Groq dashboard)
4. Review backend logs: 
   ```bash
   cd honeypot
   tail -f error.log | grep CHAT
   ```
5. Test LLM connection:
   ```bash
   python llmtest.py
   ```
6. Ensure MongoDB is running and accessible
7. Check browser console for frontend errors (F12 → Console)

### Dashboard Not Loading

**Problem**: Frontend shows connection error

**Solutions**:
1. Verify honeypot is running: `curl http://localhost:8080/api/analytics/summary`
2. Check CORS settings in `main.py`
3. Verify frontend `.env` has correct `NEXT_PUBLIC_API_URL`
4. Clear browser cache and reload
5. Check browser console for CORS errors
6. Restart both frontend and backend:
   ```bash
   # Terminal 1
   cd honeypot && uvicorn main:app --reload --port 8080
   
   # Terminal 2
   cd frontend && npm run dev
   ```

### MongoDB Connection Issues

**Problem**: Cannot connect to database

**Solutions**:
1. Verify MongoDB is running: `systemctl status mongodb`
2. Check `MONGO_URI` in `.env` file
3. Test connection:
   ```bash
   mongosh "mongodb://localhost:27017/shadow_guardian"
   ```
4. For MongoDB Atlas, check:
   - Connection string format
   - Network access whitelist (add your IP)
   - Database user credentials
5. Check firewall rules allow port 27017

---

## Configuration Summary

Here's a complete `.env` file template:

```bash
# ============================================================================
# QuantumShield Complete Configuration
# ============================================================================

# Upstream Service (DVWA)
UPSTREAM_URL=http://localhost:3000

# Database
MONGO_URI=mongodb://localhost:27017
DB_NAME=shadow_guardian

# LLM / AI Chatbot
GROQ_API_KEY=your_groq_or_openai_key_here
LLM_MODEL=llama-3.1-70b-versatile
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=100000

# Email Alerts (SendGrid)
ENABLE_EMAIL_ALERTS=true
SENDGRID_API_KEY=SG.XXXXXXXXXXXXXXXXXXXX
ALERT_FROM_EMAIL=alerts@yourdomain.com
ALERT_TO_EMAIL=security@yourdomain.com

# Slack Alerts
ENABLE_SLACK_ALERTS=true
SLACK_WEBHOOK_URL=<your-slack-webhook-url>
SLACK_CHANNEL=#security-alerts

# Honeypot Settings
HONEYPOT_NAME=QuantumShield
SYSTEM_PERSONA=Ubuntu 22.04 LTS
RATE_LIMIT_PER_MINUTE=10

# Cache
CACHE_TTL_SECONDS=3600
CACHE_MAX_SIZE=1000
```

---

## Advanced Configuration

### Custom Slack Message Formatting

Edit `honeypot/core/slack_notifier.py` to customize message format:

```python
# Change alert color based on severity
def _get_severity_indicators(self, ml_verdict: str, ml_confidence: float):
    if ml_confidence >= 0.95:
        return ("🔴", "danger")  # Red for critical
    elif ml_confidence >= 0.85:
        return ("🟠", "#FF9800")  # Orange for high
    else:
        return ("🟡", "warning")  # Yellow for medium
```

### Email Alert Thresholds

Edit `honeypot/core/email_notifier.py`:

```python
# Only send email for confidence >= 90%
async def send_attack_alert(self, ..., ml_confidence: float):
    if ml_confidence < 0.90:  # Threshold
        return  # Skip email
    # ... rest of code
```

### Scheduled Summary Reports

Create a cron job for hourly summaries:

```bash
# Add to crontab: crontab -e
0 * * * * cd /path/to/honeypot && python scripts/send_summary.py
```

Create `scripts/send_summary.py`:

```python
import asyncio
from core.slack_notifier import slack_notifier
from core.database import db
from datetime import datetime, timedelta

async def send_hourly_summary():
    await db.connect()
    
    # Query last hour's data
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    logs = await db.get_collection("logs").find({
        "timestamp": {"$gte": one_hour_ago}
    }).to_list(length=1000)
    
    # Aggregate statistics
    total_attacks = len(logs)
    malicious_count = sum(1 for log in logs if log.get("ml_verdict") == "MALICIOUS")
    
    # Top attackers
    ip_counts = {}
    for log in logs:
        ip = log.get("ip")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_attackers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Attack types
    attack_types = {}
    for log in logs:
        atype = log.get("attack_type", "Unknown")
        attack_types[atype] = attack_types.get(atype, 0) + 1
    
    # Send summary
    await slack_notifier.send_summary_alert(
        total_attacks=total_attacks,
        malicious_count=malicious_count,
        top_attackers=top_attackers,
        attack_types=attack_types,
        time_period="Last Hour"
    )
    
    await db.close()

if __name__ == "__main__":
    asyncio.run(send_hourly_summary())
```

---

## Support & Resources

- **Documentation**: See `architecture-diagram.md` for system architecture
- **GitHub Issues**: Report bugs and request features
- **Slack Community**: Join our security community (link)
- **Email Support**: support@quantumshield.io

---

**Last Updated**: December 23, 2025  
**Version**: 1.0  
**Project**: QuantumShield Security Monitoring System

