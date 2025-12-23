# GCP Cloud Run Deployment Guide

This guide explains how to deploy the Honeypot Security System to Google Cloud Platform using Cloud Run.

## Prerequisites

1. **Google Cloud SDK**: Install from https://cloud.google.com/sdk/docs/install
2. **GCP Project**: Project ID: `dec25-intern-a-security`
3. **MongoDB Atlas Account**: Free tier available at https://cloud.mongodb.com

## Quick Start

### Step 1: Set Up MongoDB Atlas (Free Tier)

1. Go to https://cloud.mongodb.com and create a free account
2. Create a new cluster (M0 free tier)
3. Create a database user with read/write access
4. Whitelist IP `0.0.0.0/0` (for Cloud Run access)
5. Get your connection string: `mongodb+srv://<username>:<password>@<cluster>.mongodb.net/shadow_guardian`

### Step 2: Get Your API Keys

- **Groq API Key**: Get from https://console.groq.com
- **SendGrid API Key** (optional): Get from https://sendgrid.com

### Step 3: Run the Deployment Script

**PowerShell (Windows):**
```powershell
cd deploy
.\gcp-deploy.ps1 `
    -MongoUri "mongodb+srv://user:pass@cluster.mongodb.net/shadow_guardian" `
    -GroqApiKey "your_groq_api_key"
```

**Bash (Linux/Mac/WSL):**
```bash
cd deploy
chmod +x gcp-deploy.sh
./gcp-deploy.sh \
    --mongo-uri "mongodb+srv://user:pass@cluster.mongodb.net/shadow_guardian" \
    --groq-api-key "your_groq_api_key"
```

### Step 4: Access Your Services

After deployment, you'll see URLs like:
- **Dashboard**: https://frontend-xxxxx-uc.a.run.app
- **Honeypot API**: https://honeypot-xxxxx-uc.a.run.app
- **DVWA**: https://dvwa-xxxxx-uc.a.run.app

## Manual Deployment Steps

If you prefer to deploy manually:

### 1. Enable APIs
```bash
gcloud config set project dec25-intern-a-security
gcloud services enable run.googleapis.com secretmanager.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
```

### 2. Create Artifact Registry
```bash
gcloud artifacts repositories create honeypot-repo --repository-format=docker --location=us-central1
```

### 3. Store Secrets
```bash
echo -n "your_mongo_uri" | gcloud secrets create MONGO_URI --data-file=-
echo -n "your_groq_api_key" | gcloud secrets create GROQ_API_KEY --data-file=-
```

### 4. Build Images
```bash
# From project root
cd dvwa && gcloud builds submit --tag us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/dvwa:latest
cd ../honeypot && gcloud builds submit --tag us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/honeypot:latest
cd ../frontend && gcloud builds submit --tag us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/frontend:latest
```

### 5. Deploy Services
```bash
# Deploy DVWA
gcloud run deploy dvwa \
    --image us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/dvwa:latest \
    --platform managed --region us-central1 --allow-unauthenticated \
    --memory 512Mi --cpu 1 --port 8080

# Get DVWA URL
DVWA_URL=$(gcloud run services describe dvwa --region=us-central1 --format="value(status.url)")

# Deploy Honeypot
gcloud run deploy honeypot \
    --image us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/honeypot:latest \
    --platform managed --region us-central1 --allow-unauthenticated \
    --memory 2Gi --cpu 2 --port 8080 --timeout 300 \
    --set-secrets "MONGO_URI=MONGO_URI:latest,GROQ_API_KEY=GROQ_API_KEY:latest" \
    --set-env-vars "UPSTREAM_URL=${DVWA_URL},ENABLE_EMAIL_ALERTS=false"

# Get Honeypot URL
HONEYPOT_URL=$(gcloud run services describe honeypot --region=us-central1 --format="value(status.url)")

# Deploy Frontend
gcloud run deploy frontend \
    --image us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/frontend:latest \
    --platform managed --region us-central1 --allow-unauthenticated \
    --memory 512Mi --cpu 1 --port 8080 \
    --set-env-vars "NEXT_PUBLIC_API_URL=${HONEYPOT_URL}"
```

## Troubleshooting

### View Logs
```bash
gcloud run logs read honeypot --region=us-central1 --limit=100
gcloud run logs read dvwa --region=us-central1 --limit=100
gcloud run logs read frontend --region=us-central1 --limit=100
```

### Check Service Status
```bash
gcloud run services list --region=us-central1
```

### Update a Service
```bash
# Rebuild and redeploy honeypot
cd honeypot
gcloud builds submit --tag us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/honeypot:latest
gcloud run deploy honeypot --image us-central1-docker.pkg.dev/dec25-intern-a-security/honeypot-repo/honeypot:latest --region us-central1
```

### Delete All Services
```bash
gcloud run services delete dvwa --region=us-central1 --quiet
gcloud run services delete honeypot --region=us-central1 --quiet
gcloud run services delete frontend --region=us-central1 --quiet
```

## Cost Estimation

| Service | Monthly Estimate |
|---------|-----------------|
| Cloud Run (3 services, low traffic) | $0-5 |
| MongoDB Atlas Free Tier | $0 |
| Artifact Registry | $0-2 |
| Secret Manager | $0 |
| **Total** | **$0-10/month** |

Cloud Run scales to zero when not in use, so costs are minimal for demo/dev environments.



