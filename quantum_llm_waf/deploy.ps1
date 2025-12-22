# PowerShell deployment script for Google Cloud Run

$ErrorActionPreference = "Stop"

# Configuration
$PROJECT_ID = if ($env:GCP_PROJECT_ID) { $env:GCP_PROJECT_ID } else { "your-project-id" }
$SERVICE_NAME = if ($env:SERVICE_NAME) { $env:SERVICE_NAME } else { "quantum-llm-waf-chatbot" }
$REGION = if ($env:REGION) { $env:REGION } else { "us-central1" }
$IMAGE_NAME = "gcr.io/$PROJECT_ID/$SERVICE_NAME"

Write-Host "🚀 Deploying Quantum LLM WAF Secure Chatbot to Google Cloud Run" -ForegroundColor Cyan
Write-Host "Project ID: $PROJECT_ID"
Write-Host "Service Name: $SERVICE_NAME"
Write-Host "Region: $REGION"
Write-Host ""

# Check if gcloud is installed
try {
    gcloud --version | Out-Null
} catch {
    Write-Host "❌ Error: gcloud CLI is not installed" -ForegroundColor Red
    Write-Host "Install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
}

# Check if docker is installed
try {
    docker --version | Out-Null
} catch {
    Write-Host "❌ Error: Docker is not installed" -ForegroundColor Red
    Write-Host "Install it from: https://docs.docker.com/get-docker/"
    exit 1
}

# Set the project
Write-Host "📋 Setting GCP project..." -ForegroundColor Yellow
gcloud config set project $PROJECT_ID

# Enable required APIs
Write-Host "🔧 Enabling required APIs..." -ForegroundColor Yellow
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Build and push the Docker image
Write-Host "🐳 Building Docker image..." -ForegroundColor Yellow
gcloud builds submit --tag $IMAGE_NAME

# Deploy to Cloud Run
Write-Host "☁️  Deploying to Cloud Run..." -ForegroundColor Yellow

# Check if secrets exist, use environment variables as fallback
$secretsArgs = @()
try {
    gcloud secrets describe openai-api-key --quiet 2>$null
    $secretsArgs += "--set-secrets"
    $secretsArgs += "OPENAI_API_KEY=openai-api-key:latest"
} catch {
    Write-Host "⚠️  Warning: openai-api-key secret not found. Using environment variable." -ForegroundColor Yellow
    $secretsArgs += "--set-env-vars"
    $secretsArgs += "OPENAI_API_KEY=$env:OPENAI_API_KEY"
}

try {
    gcloud secrets describe hf-token --quiet 2>$null
    if ($secretsArgs -contains "--set-secrets") {
        $secretsArgs[-1] = $secretsArgs[-1] + ",HF_TOKEN=hf-token:latest"
    } else {
        $secretsArgs += "--set-secrets"
        $secretsArgs += "HF_TOKEN=hf-token:latest"
    }
} catch {
    Write-Host "ℹ️  Info: hf-token secret not found (optional)." -ForegroundColor Cyan
}

try {
    gcloud secrets describe openai-model --quiet 2>$null
    if ($secretsArgs -contains "--set-secrets") {
        $secretsArgs[-1] = $secretsArgs[-1] + ",OPENAI_MODEL=openai-model:latest"
    } else {
        $secretsArgs += "--set-secrets"
        $secretsArgs += "OPENAI_MODEL=openai-model:latest"
    }
} catch {
    Write-Host "ℹ️  Info: openai-model secret not found. Using default (gpt-4o-mini)." -ForegroundColor Cyan
}

$deployArgs = @(
    "run", "deploy", $SERVICE_NAME,
    "--image", $IMAGE_NAME,
    "--platform", "managed",
    "--region", $REGION,
    "--allow-unauthenticated",
    "--memory", "2Gi",
    "--cpu", "2",
    "--timeout", "300",
    "--max-instances", "10",
    "--set-env-vars", "PYTHONPATH=/app:/app/PurpleLlama"
) + $secretsArgs

gcloud $deployArgs

# Get the service URL
$SERVICE_URL = gcloud run services describe $SERVICE_NAME `
    --platform managed `
    --region $REGION `
    --format 'value(status.url)'

Write-Host ""
Write-Host "✅ Deployment successful!" -ForegroundColor Green
Write-Host "🌐 Service URL: $SERVICE_URL" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Note: Make sure to set up secrets in Secret Manager:" -ForegroundColor Yellow
Write-Host "   - openai-api-key"
Write-Host "   - hf-token (optional)"
Write-Host "   - openai-model (optional, defaults to gpt-4o-mini)"
Write-Host ""
Write-Host "To set secrets, run:" -ForegroundColor Yellow
Write-Host "  echo 'your-api-key' | gcloud secrets create openai-api-key --data-file=-"
Write-Host "  echo 'your-hf-token' | gcloud secrets create hf-token --data-file=-"
Write-Host "  echo 'gpt-4o-mini' | gcloud secrets create openai-model --data-file=-"

