# 🚀 Docker Deployment - Quick Guide

## Services

All services accessible directly via VPS IP:

- **DVWA**: `http://YOUR_VPS_IP:3000`
- **Honeypot**: `http://YOUR_VPS_IP:8000`
- **Frontend**: `http://YOUR_VPS_IP:3001`

## Minimal .env Setup

Only 2 variables required in `.env`:

```env
GROQ_API_KEY=your_groq_api_key
MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/
```

All other variables have defaults in `docker-compose.yml`!

## Deploy

```bash
# 1. Create .env with your credentials
cp .env.example .env
nano .env

# 2. Build and start
docker compose build
docker compose up -d

# 3. Check status
docker compose ps
docker compose logs -f
```

## Override Defaults (Optional)

Add to your `.env` to override defaults:

```env
# Database
DB_NAME=shadow_guardian

# Honeypot
HONEYPOT_NAME=QuantumShield
SYSTEM_PERSONA=Ubuntu 22.04 LTS
RATE_LIMIT_PER_MINUTE=10

# LLM
LLM_MODEL=llama-3.3-70b-versatile
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=1024

# Email Alerts
ENABLE_EMAIL_ALERTS=true
SENDGRID_API_KEY=your_key
ALERT_FROM_EMAIL=from@example.com
ALERT_TO_EMAIL=to@example.com
```

## Important Notes

✅ **UPSTREAM_URL is hardcoded** to `http://dvwa:3000` in docker-compose.yml (Docker service name)  
✅ **All services bind to 0.0.0.0** inside containers  
✅ **Services communicate via Docker network** using service names  
✅ **MongoDB is external** (MongoDB Atlas or hosted)

## Commands

```bash
# View logs
docker compose logs -f honeypot

# Restart a service  
docker compose restart honeypot

# Stop all
docker compose down

# Rebuild
docker compose up -d --build
```

Done! 🎉
