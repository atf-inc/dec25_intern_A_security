# PowerShell script to fix Cloud Build permissions

$ErrorActionPreference = "Stop"

$PROJECT_ID = if ($env:GCP_PROJECT_ID) { $env:GCP_PROJECT_ID } else { "dec25-intern-a-security" }

Write-Host "Fixing Cloud Build permissions for project: $PROJECT_ID" -ForegroundColor Cyan

# Get project number
$PROJECT_NUMBER = gcloud projects describe $PROJECT_ID --format="value(projectNumber)"
$SERVICE_ACCOUNT = "$PROJECT_NUMBER@cloudbuild.gserviceaccount.com"

Write-Host "Project Number: $PROJECT_NUMBER"
Write-Host "Service Account: $SERVICE_ACCOUNT"

# Grant necessary roles to Cloud Build service account
Write-Host "Granting roles to Cloud Build service account..." -ForegroundColor Yellow

# Storage Admin - for accessing GCS buckets
Write-Host "  - Granting Storage Admin role..." -ForegroundColor Yellow
gcloud projects add-iam-policy-binding $PROJECT_ID `
    --member="serviceAccount:$SERVICE_ACCOUNT" `
    --role="roles/storage.admin"

# Service Account User - for using service accounts
Write-Host "  - Granting Service Account User role..." -ForegroundColor Yellow
gcloud projects add-iam-policy-binding $PROJECT_ID `
    --member="serviceAccount:$SERVICE_ACCOUNT" `
    --role="roles/iam.serviceAccountUser"

# Cloud Run Admin - for deploying to Cloud Run
Write-Host "  - Granting Cloud Run Admin role..." -ForegroundColor Yellow
gcloud projects add-iam-policy-binding $PROJECT_ID `
    --member="serviceAccount:$SERVICE_ACCOUNT" `
    --role="roles/run.admin"

# Secret Manager Secret Accessor - for accessing secrets
Write-Host "  - Granting Secret Manager Secret Accessor role..." -ForegroundColor Yellow
gcloud projects add-iam-policy-binding $PROJECT_ID `
    --member="serviceAccount:$SERVICE_ACCOUNT" `
    --role="roles/secretmanager.secretAccessor"

Write-Host ""
Write-Host "Permissions granted!" -ForegroundColor Green
Write-Host ""
Write-Host "Now try building again:" -ForegroundColor Yellow
$buildCmd = "gcloud builds submit --tag gcr.io/" + $PROJECT_ID + "/quantum-llm-waf-chatbot"
Write-Host "  $buildCmd" -ForegroundColor Cyan
