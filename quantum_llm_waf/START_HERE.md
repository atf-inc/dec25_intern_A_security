# 🚀 Quick Start - Deploy to Google Cloud Run

## Prerequisites

1. **Google Cloud Account** (with billing enabled)
2. **gcloud CLI** installed: https://cloud.google.com/sdk/docs/install
3. **Docker** installed: https://docs.docker.com/get-docker/
4. **OpenAI API Key** (required)
5. **GCP Permissions**: You need either:
   - IAM permissions to grant roles to Cloud Build service account, OR
   - Use the local Docker build method (see below)

## Quick Deployment (3 Steps)

### Step 1: Set Your Project ID

**Windows PowerShell:**
```powershell
$env:GCP_PROJECT_ID = "your-gcp-project-id"
```

**Linux/Mac:**
```bash
export GCP_PROJECT_ID="your-gcp-project-id"
```

### Step 2: Create Secrets

```bash
# Create OpenAI API Key secret
echo "sk-your-openai-api-key" | gcloud secrets create openai-api-key --data-file=-

# Optional: HuggingFace token
echo "your-hf-token" | gcloud secrets create hf-token --data-file=-

# Optional: OpenAI model (defaults to gpt-4o-mini)
echo "gpt-4o-mini" | gcloud secrets create openai-model --data-file=-
```

### Step 3: Fix Permissions (If Needed)

If you get permission errors, you have two options:

**Option A: Ask Admin to Grant Permissions**
- See `FIX_PERMISSIONS.md` for details
- Admin needs to grant roles to Cloud Build service account

**Option B: Use Local Docker Build (No IAM permissions needed)**

**Windows:**
```powershell
.\deploy_local_docker.ps1
```

**Linux/Mac:**
```bash
chmod +x deploy_local_docker.sh
./deploy_local_docker.sh
```

### Step 4: Deploy (If permissions are fixed)

**Windows:**
```powershell
.\deploy.ps1
```

**Linux/Mac:**
```bash
chmod +x deploy.sh
./deploy.sh
```

## Get Your Service URL

After deployment, the script will show your service URL, or get it with:

```bash
gcloud run services describe quantum-llm-waf-chatbot \
    --platform managed \
    --region us-central1 \
    --format 'value(status.url)'
```

## Test Locally First (Optional)

Before deploying, test locally:

```bash
cd secure_agent
python web_app.py
```

Then visit: http://localhost:8080

## What You Get

- ✅ Secure chatbot web interface
- ✅ Protected by Prompt-Guard-86M (local model)
- ✅ Protected by CodeShield (code security)
- ✅ Protected by ChatGPT Guard (API-based)
- ✅ Real-time blocking of unsafe content
- ✅ Beautiful, responsive UI

## Full Documentation

- `DEPLOYMENT_GUIDE.md` - Complete deployment guide
- `QUICK_DEPLOY.md` - Quick reference
- `README_DEPLOYMENT.md` - Deployment summary

## Troubleshooting

If deployment fails:
1. Check `gcloud auth login` - you're logged in
2. Check `gcloud config set project YOUR_PROJECT_ID`
3. Verify secrets exist: `gcloud secrets list`
4. Check Docker is running: `docker ps`

## Support

For detailed instructions, see `DEPLOYMENT_GUIDE.md`

