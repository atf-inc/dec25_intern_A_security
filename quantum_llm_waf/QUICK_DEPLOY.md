# Quick Deployment Guide

## Prerequisites Check

```bash
# Check gcloud
gcloud --version

# Check docker
docker --version

# Login to GCP
gcloud auth login
gcloud auth configure-docker
```

## Step 1: Set Your Project ID

**Windows PowerShell:**
```powershell
$env:GCP_PROJECT_ID = "your-project-id"
$env:SERVICE_NAME = "quantum-llm-waf-chatbot"
$env:REGION = "us-central1"
```

**Linux/Mac:**
```bash
export GCP_PROJECT_ID="your-project-id"
export SERVICE_NAME="quantum-llm-waf-chatbot"
export REGION="us-central1"
```

## Step 2: Create Secrets

```bash
# Create OpenAI API Key secret
echo "sk-your-openai-key" | gcloud secrets create openai-api-key --data-file=-

# Create HuggingFace token (optional)
echo "your-hf-token" | gcloud secrets create hf-token --data-file=-

# Create OpenAI model (optional)
echo "gpt-4o-mini" | gcloud secrets create openai-model --data-file=-
```

## Step 3: Deploy

**Windows:**
```powershell
.\deploy.ps1
```

**Linux/Mac:**
```bash
chmod +x deploy.sh
./deploy.sh
```

## Step 4: Get Your Service URL

After deployment completes, you'll see the service URL in the output.

Or get it manually:
```bash
gcloud run services describe quantum-llm-waf-chatbot \
    --platform managed \
    --region us-central1 \
    --format 'value(status.url)'
```

## That's It! 🎉

Open the URL in your browser to use the secure chatbot.

