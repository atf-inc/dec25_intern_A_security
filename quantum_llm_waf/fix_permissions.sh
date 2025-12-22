#!/bin/bash
# Fix Cloud Build permissions

set -e

PROJECT_ID=${GCP_PROJECT_ID:-"dec25-intern-a-security"}

echo "🔧 Fixing Cloud Build permissions for project: ${PROJECT_ID}"

# Get project number
PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} --format="value(projectNumber)")
SERVICE_ACCOUNT="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

echo "Project Number: ${PROJECT_NUMBER}"
echo "Service Account: ${SERVICE_ACCOUNT}"

# Grant necessary roles to Cloud Build service account
echo "Granting roles to Cloud Build service account..."

# Storage Admin - for accessing GCS buckets
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/storage.admin"

# Service Account User - for using service accounts
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/iam.serviceAccountUser"

# Cloud Run Admin - for deploying to Cloud Run
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/run.admin"

# Secret Manager Secret Accessor - for accessing secrets
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor"

echo "✅ Permissions granted!"
echo ""
echo "Now try building again:"
echo "  gcloud builds submit --tag gcr.io/${PROJECT_ID}/quantum-llm-waf-chatbot"

