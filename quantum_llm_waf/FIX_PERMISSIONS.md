# Fix Cloud Build Permissions

## Issue
You're getting a permission error because the Cloud Build service account needs additional permissions.

## Solution Options

### Option 1: Ask Project Owner/Admin (Recommended)

Ask your GCP project owner/admin to run these commands:

```bash
PROJECT_ID="dec25-intern-a-security"
PROJECT_NUMBER="1015557087390"
SERVICE_ACCOUNT="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

# Grant Storage Admin role
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/storage.admin"

# Grant Service Account User role
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/iam.serviceAccountUser"

# Grant Cloud Run Admin role
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/run.admin"

# Grant Secret Manager Secret Accessor role
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor"
```

### Option 2: Use Cloud Console (If you have access)

1. Go to: https://console.cloud.google.com/iam-admin/iam?project=dec25-intern-a-security
2. Find the service account: `1015557087390@cloudbuild.gserviceaccount.com`
3. Click "Edit" (pencil icon)
4. Add these roles:
   - Storage Admin
   - Service Account User
   - Cloud Run Admin
   - Secret Manager Secret Accessor

### Option 3: Alternative - Use Docker Build Locally

If you can't get permissions, you can build locally and push:

```bash
# Build locally
docker build -t gcr.io/dec25-intern-a-security/quantum-llm-waf-chatbot .

# Configure Docker for GCR
gcloud auth configure-docker

# Push the image
docker push gcr.io/dec25-intern-a-security/quantum-llm-waf-chatbot

# Then deploy
gcloud run deploy quantum-llm-waf-chatbot \
    --image gcr.io/dec25-intern-a-security/quantum-llm-waf-chatbot \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 2 \
    --timeout 300 \
    --max-instances 10 \
    --set-env-vars "PYTHONPATH=/app:/app/PurpleLlama" \
    --set-secrets "OPENAI_API_KEY=openai-api-key:latest"
```

### Option 4: Request Required IAM Role

Ask your admin to grant you one of these roles:
- **Project IAM Admin** (`roles/resourcemanager.projectIamAdmin`)
- **Owner** (`roles/owner`)
- **Editor** (`roles/editor`) - may work for some operations

## After Permissions Are Fixed

Once permissions are granted, you can build and deploy:

```bash
# Build and push
gcloud builds submit --tag gcr.io/dec25-intern-a-security/quantum-llm-waf-chatbot

# Or use the deployment script
.\deploy.ps1
```

## Quick Check

To check if you have the right permissions:

```bash
# Check your current roles
gcloud projects get-iam-policy dec25-intern-a-security \
    --flatten="bindings[].members" \
    --filter="bindings.members:shubhamkumariiitj@gmail.com" \
    --format="table(bindings.role)"
```

## Contact Information

If you need help, provide this information to your GCP admin:

- **Project ID**: `dec25-intern-a-security`
- **Project Number**: `1015557087390`
- **Service Account**: `1015557087390@cloudbuild.gserviceaccount.com`
- **Required Roles**: Storage Admin, Service Account User, Cloud Run Admin, Secret Manager Secret Accessor

