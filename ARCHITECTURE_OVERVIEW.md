# QuantumShield - System Architecture Overview

## Quick Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         QUANTUMSHIELD SECURITY SYSTEM                   │
└─────────────────────────────────────────────────────────────────────────┘

        👤 Security Admin                      🔴 Attackers
             │                                      │
             │ View Dashboard                       │ Malicious Requests
             ▼                                      ▼
    ┌──────────────────┐                  ┌──────────────────┐
    │   FRONTEND       │◄─────────────────│   HONEYPOT/WAF   │
    │   Dashboard      │  Attack Data     │   (Port 8080)    │
    │   (Port 3001)    │                  │                  │
    │                  │                  │  ┌─────────────┐ │
    │ • Live Feed      │                  │  │ ML Firewall │ │
    │ • Analytics      │                  │  │ XGBoost     │ │
    │ • AI Chatbot 🤖  │                  │  └─────────────┘ │
    │ • Reports        │                  │                  │
    └──────────────────┘                  │  ┌─────────────┐ │
             │                             │  │ Deception   │ │
             │ Chat API                    │  │ Engine      │ │
             └─────────────────────────────┤  └─────────────┘ │
                                           └──────┬───────────┘
                                                  │ Proxy
                                                  ▼
                                         ┌──────────────────┐
                                         │      DVWA        │
                                         │  Vulnerable App  │
                                         │   (Port 3000)    │
                                         └──────────────────┘

    ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
    │   📧 EMAIL       │      │   💬 SLACK       │      │   🧠 LLM         │
    │   SendGrid API   │      │   Webhook API    │      │   OpenAI/Groq    │
    │                  │      │                  │      │                  │
    │ • MALICIOUS      │      │ • Real-time      │      │ • NL Queries     │
    │   Alerts         │      │   Alerts         │      │ • Forensics      │
    │ • HTML Reports   │      │ • @channel       │      │ • Intent         │
    └──────────────────┘      │ • Summaries      │      │   Analysis       │
                              └──────────────────┘      └──────────────────┘
                                       │                          │
                                       └────────┬─────────────────┘
                                                ▼
                                       ┌──────────────────┐
                                       │   🗄️ MongoDB     │
                                       │   Database       │
                                       │                  │
                                       │ • Attack Logs    │
                                       │ • Sessions       │
                                       │ • Analytics      │
                                       └──────────────────┘
```

---

## Component Breakdown

### 1. 🎨 Frontend Dashboard (Next.js)
- **Port**: 3001
- **Tech**: Next.js 16, React 19, TypeScript, TailwindCSS
- **Features**:
  - Real-time attack feed
  - Interactive charts (Recharts)
  - AI chatbot interface
  - Session management
  - Report generation

### 2. 🎯 DVWA - Vulnerable Honeypot Target
- **Port**: 3000
- **Tech**: Next.js, SQLite
- **Purpose**: Intentionally vulnerable web app to attract attackers
- **Vulnerabilities**:
  - SQL Injection
  - XSS
  - Authentication bypass

### 3. 🛡️ QuantumShield Honeypot/WAF
- **Port**: 8080
- **Tech**: FastAPI, Python
- **Core Functions**:
  - Reverse proxy to DVWA
  - ML-based attack detection
  - Deception engine
  - Session tracking
  - Real-time logging

### 4. 🧠 AI & ML Components
- **LLM**: OpenAI GPT-4 / Groq
- **ML Classifiers**:
  - SQL Injection Detector (BERT)
  - Network Traffic Classifier (XGBoost)
- **Functions**:
  - Natural language query translation
  - Forensics analysis
  - Attack intent detection

### 5. 📧 Email Alerts (SendGrid)
- **Trigger**: MALICIOUS verdict (confidence ≥ 80%)
- **Content**:
  - Attack details
  - Payload preview
  - ML confidence score
  - HTML formatted

### 6. 💬 Slack Integration
- **Types**:
  - Real-time attack alerts
  - Summary reports
  - Critical threat notifications
- **Features**:
  - Rich message formatting
  - Action buttons
  - @channel mentions

### 7. 🗄️ MongoDB Database
- **Collections**:
  - `logs`: Attack records
  - `sessions`: Attacker sessions
  - `analytics`: Aggregated stats

---

## Data Flow - Attack Detection

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ATTACK FLOW                                   │
└──────────────────────────────────────────────────────────────────────┘

1. Attacker → HTTP Request
             │
             ▼
2. Honeypot WAF → Intercept & Analyze
             │
             ├─→ Extract Features
             │   (Method, Path, Payload, Headers)
             │
             ▼
3. ML Classifier → Predict
             │
             ├─→ SAFE (confidence < 0.6)
             │   └─→ Forward to DVWA
             │
             ├─→ SUSPICIOUS (0.6 ≤ confidence < 0.8)
             │   └─→ Route to Honeypot (Deception)
             │
             └─→ MALICIOUS (confidence ≥ 0.8)
                 │
                 ├─→ Block Request (403)
                 ├─→ Log to MongoDB
                 ├─→ 📧 Send Email Alert
                 └─→ 💬 Send Slack Alert

4. Admin Views in Dashboard
             │
             ▼
5. AI Chatbot Analyzes Session
             │
             └─→ Forensics Report
```

---

## Data Flow - Chatbot Query

```
┌──────────────────────────────────────────────────────────────────────┐
│                      CHATBOT QUERY FLOW                              │
└──────────────────────────────────────────────────────────────────────┘

1. User → Natural Language Question
         "Show me SQL injections from the last hour"
             │
             ▼
2. Frontend → POST /api/chat/query
             │
             ▼
3. Honeypot → Send to LLM
             │
             ▼
4. LLM → Parse Intent & Generate MongoDB Query
         {
           collection: "logs",
           pipeline: [
             {$match: {attack_type: "sql_injection", timestamp: {$gte: ...}}},
             {$sort: {timestamp: -1}}
           ],
           render_type: "table"
         }
             │
             ▼
5. Honeypot → Execute Query on MongoDB
             │
             ▼
6. MongoDB → Return Results
             │
             ▼
7. Honeypot → Format Data
             │
             ▼
8. Frontend → Render Table/Chart
             │
             ▼
9. User Sees Results
```

---

## Alert Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ALERT SYSTEM                                  │
└──────────────────────────────────────────────────────────────────────┘

    ML Verdict: MALICIOUS + Confidence ≥ 80%
                      │
                      ├─────────────────────────────┐
                      │                             │
                      ▼                             ▼
              ┌───────────────┐            ┌───────────────┐
              │  📧 EMAIL     │            │  💬 SLACK     │
              │  ALERT        │            │  ALERT        │
              └───────────────┘            └───────────────┘
                      │                             │
                      │                             │
                      ▼                             ▼
              ┌───────────────┐            ┌───────────────┐
              │ SendGrid API  │            │ Webhook POST  │
              │               │            │               │
              │ • HTML Email  │            │ • Block Kit   │
              │ • Payload     │            │ • Action Btns │
              │ • Confidence  │            │ • Severity    │
              └───────────────┘            └───────────────┘
                      │                             │
                      ▼                             ▼
              Security Admin Inbox         Slack Channel
```

---

## Technology Stack

| Layer | Technology | Language | Purpose |
|-------|-----------|----------|---------|
| **Frontend** | Next.js 16, React 19 | TypeScript | Dashboard UI |
| **Honeypot** | FastAPI | Python | WAF & Security Logic |
| **DVWA** | Next.js | TypeScript | Vulnerable Target |
| **Database** | MongoDB | - | Data Storage |
| **Cache** | Redis | - | Session State |
| **AI/ML** | OpenAI/Groq API | Python | NLP & Forensics |
| **ML Models** | XGBoost, BERT | Python | Attack Detection |
| **Email** | SendGrid API | - | Email Alerts |
| **Chat** | Slack Webhook | - | Team Notifications |
| **Deploy** | Google Cloud Run | - | Cloud Hosting |

---

## Key Integrations

### Slack Integration
```yaml
Setup:
  1. Create Slack App at api.slack.com/apps
  2. Enable Incoming Webhooks
  3. Get Webhook URL
  4. Configure in .env:
     ENABLE_SLACK_ALERTS=true
     SLACK_WEBHOOK_URL=<your-slack-webhook-url>
     SLACK_CHANNEL=#security-alerts

Features:
  - Real-time attack alerts
  - Summary reports (hourly/daily)
  - Critical threat notifications
  - Rich message formatting
  - Action buttons
```

### Email Integration
```yaml
Setup:
  1. Create SendGrid account
  2. Generate API Key
  3. Verify sender email
  4. Configure in .env:
     ENABLE_EMAIL_ALERTS=true
     SENDGRID_API_KEY=SG...
     ALERT_FROM_EMAIL=alerts@domain.com
     ALERT_TO_EMAIL=security@domain.com

Features:
  - HTML formatted emails
  - Attack classification
  - Payload preview
  - Confidence scores
  - Dashboard link
```

### Chatbot Integration
```yaml
Setup:
  1. Get OpenAI or Groq API key
  2. Configure in .env:
     GROQ_API_KEY=sk-...
     LLM_MODEL=llama-3.1-70b-versatile
     LLM_TEMPERATURE=0.7

Features:
  - Natural language queries
  - MongoDB query translation
  - Forensics analysis
  - MITRE ATT&CK mapping
  - Interactive visualizations
```

---

## Security Features

### Multi-Layer Defense
1. **ML Detection**: XGBoost classifier (95%+ accuracy)
2. **Behavioral Analysis**: Session tracking & pattern recognition
3. **Deception Technology**: Fake responses & honeytokens
4. **Automated Alerting**: Email + Slack notifications
5. **AI Forensics**: LLM-powered attack analysis

### Alert Thresholds
| Confidence | Action | Email | Slack |
|-----------|--------|-------|-------|
| < 60% | Forward to DVWA | ❌ | ❌ |
| 60-79% | Route to Honeypot | ❌ | ❌ |
| 80-89% | Block + Alert | ✅ | ✅ |
| ≥ 90% | Block + Critical Alert | ✅ | ✅ @channel |

---

## API Endpoints

### Analytics & Data
```
GET  /api/analytics/summary          - Attack statistics
GET  /api/analytics/live-attacks     - Real-time feed
GET  /api/sessions                   - Active sessions
GET  /api/analytics/top-ips          - Top attacking IPs
GET  /api/analytics/attack-types     - Attack distribution
```

### AI Chatbot
```
POST /api/chat/query                 - Natural language query
POST /api/chat/forensics/{session}   - Session analysis
GET  /api/chat/suggestions           - Query suggestions
```

### Honeypot (Internal)
```
*    /*                              - Proxied requests
```

---

## Environment Configuration

**Minimal Configuration** (`.env`):
```bash
# Required
UPSTREAM_URL=http://localhost:3000
MONGO_URI=mongodb://localhost:27017
GROQ_API_KEY=your_api_key_here

# Email Alerts (Optional)
ENABLE_EMAIL_ALERTS=true
SENDGRID_API_KEY=SG...
ALERT_FROM_EMAIL=alerts@domain.com
ALERT_TO_EMAIL=security@domain.com

# Slack Alerts (Optional)
ENABLE_SLACK_ALERTS=true
SLACK_WEBHOOK_URL=<your-slack-webhook-url>
SLACK_CHANNEL=#security-alerts
```

---

## Quick Start

### 1. Start MongoDB
```bash
# Local
mongod --dbpath /path/to/data

# Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### 2. Configure Environment
```bash
cd honeypot
cp env.example .env
# Edit .env with your API keys
```

### 3. Start Services
```bash
# Terminal 1: Honeypot/WAF
cd honeypot
pip install -r requirements.txt
uvicorn main:app --reload --port 8080

# Terminal 2: DVWA
cd dvwa
npm install
npm run dev  # Port 3000

# Terminal 3: Frontend Dashboard
cd frontend
npm install
npm run dev  # Port 3001
```

### 4. Test Integrations
```bash
# Test Slack
cd honeypot
python test_slack.py

# Test Email
python test_email.py

# Test Chatbot
# Open http://localhost:3001 and click chatbot icon
```

---

## Monitoring & Observability

### Logs
```bash
# Honeypot logs
tail -f honeypot/error.log

# Filter by component
tail -f honeypot/error.log | grep CHAT
tail -f honeypot/error.log | grep FIREWALL
```

### MongoDB Queries
```javascript
// Connect to MongoDB
mongosh "mongodb://localhost:27017/shadow_guardian"

// Recent attacks
db.logs.find().sort({timestamp: -1}).limit(10)

// Malicious attacks
db.logs.find({ml_verdict: "MALICIOUS"})

// Attack statistics
db.logs.aggregate([
  {$group: {_id: "$attack_type", count: {$sum: 1}}},
  {$sort: {count: -1}}
])
```

### Health Checks
```bash
# Honeypot health
curl http://localhost:8080/api/analytics/summary

# DVWA health
curl http://localhost:3000/api/health

# Frontend
curl http://localhost:3001
```

---

## Deployment

### Google Cloud Platform
```bash
cd deploy
./gcp-deploy.sh

# Or deploy individually
gcloud builds submit --config frontend/cloudbuild.yaml
gcloud builds submit --config dvwa/cloudbuild.yaml
gcloud builds submit --config honeypot/cloudbuild.yaml
```

### Docker Compose (Local)
```bash
docker-compose up -d
```

---

## Performance Metrics

### System Capacity
- **Requests/sec**: 100+ (single instance)
- **Attack Detection**: < 50ms latency
- **ML Inference**: < 100ms
- **LLM Response**: 2-5 seconds
- **Alert Delivery**: < 1 second

### Resource Usage
- **Honeypot**: 512MB RAM, 1 vCPU
- **Frontend**: 256MB RAM, 1 vCPU
- **DVWA**: 256MB RAM, 1 vCPU
- **MongoDB**: 512MB RAM minimum

---

## Security Considerations

### Production Checklist
- [ ] Change default MongoDB credentials
- [ ] Enable MongoDB authentication
- [ ] Use environment secrets (not .env files)
- [ ] Enable HTTPS/TLS
- [ ] Configure firewall rules
- [ ] Set rate limiting
- [ ] Enable audit logging
- [ ] Regular security updates
- [ ] Backup MongoDB regularly
- [ ] Monitor alert delivery

---

## Support

**Documentation**:
- `architecture-diagram.md` - Detailed Mermaid diagrams
- `INTEGRATION_SETUP.md` - Integration setup guides
- `README.md` - Getting started

**Testing**:
- `honeypot/test_slack.py` - Test Slack integration
- `honeypot/test_email.py` - Test email integration
- `honeypot/test_attacks.py` - Simulate attacks

**Community**:
- GitHub Issues
- Slack Community
- Email Support

---

**Generated**: December 23, 2025  
**Version**: 1.0  
**Project**: QuantumShield Security Monitoring System

