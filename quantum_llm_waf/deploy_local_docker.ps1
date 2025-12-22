# Alternative deployment using local Docker build
# Uses your GCP project credentials

$ErrorActionPreference = "Stop"

# Load environment variables from .env file if it exists
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Write-Host "Loading environment variables from .env file..." -ForegroundColor Cyan
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]*)\s*=\s*(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($key -and $value) {
                [Environment]::SetEnvironmentVariable($key, $value, "Process")
                Write-Host "  Loaded: $key" -ForegroundColor Gray
            }
        }
    }
}

# Configuration - Your GCP Project Details
$PROJECT_ID = if ($env:GCP_PROJECT_ID) { $env:GCP_PROJECT_ID } else { "dec25-intern-a-security" }
$BILLING_ACCOUNT_ID = "01D57C-E9F5E1-B230A0"
$SERVICE_NAME = if ($env:SERVICE_NAME) { $env:SERVICE_NAME } else { "quantum-llm-waf-chatbot" }
$REGION = if ($env:REGION) { $env:REGION } else { "us-central1" }
$IMAGE_NAME = "gcr.io/$PROJECT_ID/$SERVICE_NAME"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Quantum LLM WAF - Local Docker Deployment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Project ID: $PROJECT_ID" -ForegroundColor Yellow
Write-Host "Billing Account: $BILLING_ACCOUNT_ID" -ForegroundColor Yellow
Write-Host "Service Name: $SERVICE_NAME" -ForegroundColor Yellow
Write-Host "Region: $REGION" -ForegroundColor Yellow
Write-Host "Image: $IMAGE_NAME" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if gcloud is installed
try {
    gcloud --version | Out-Null
} catch {
    Write-Host "Error: gcloud CLI is not installed" -ForegroundColor Red
    Write-Host "Install it from: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

# Check if Docker is running
Write-Host "Checking Docker..." -ForegroundColor Yellow
try {
    docker ps | Out-Null
    Write-Host "  Docker is running" -ForegroundColor Green
} catch {
    Write-Host "Error: Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Set the GCP project
Write-Host "Setting GCP project..." -ForegroundColor Yellow
gcloud config set project $PROJECT_ID
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to set project. Check your gcloud authentication." -ForegroundColor Red
    exit 1
}

# Link billing account (if not already linked)
Write-Host "Checking billing account..." -ForegroundColor Yellow
$billingInfo = gcloud billing projects describe $PROJECT_ID --format="value(billingAccountName)" 2>$null
if (-not $billingInfo -or $billingInfo -eq "") {
    Write-Host "  Linking billing account..." -ForegroundColor Yellow
    gcloud billing projects link $PROJECT_ID --billing-account=$BILLING_ACCOUNT_ID
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Warning: Could not link billing account. It may already be linked or you may not have permission." -ForegroundColor Yellow
    } else {
        Write-Host "  Billing account linked" -ForegroundColor Green
    }
} else {
    Write-Host "  Billing account already linked" -ForegroundColor Green
}

# Enable required APIs
Write-Host "Enabling required APIs..." -ForegroundColor Yellow
$apis = @(
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "containerregistry.googleapis.com",
    "secretmanager.googleapis.com"
)

foreach ($api in $apis) {
    Write-Host "  Enabling $api..." -ForegroundColor Gray
    gcloud services enable $api --quiet 2>$null
}
Write-Host "  APIs enabled" -ForegroundColor Green

# Configure Docker for GCR
Write-Host "Configuring Docker for Google Container Registry..." -ForegroundColor Yellow
gcloud auth configure-docker --quiet
Write-Host "  Docker configured" -ForegroundColor Green

# Build the Docker image locally
Write-Host ""
Write-Host "Building Docker image (this may take 5-10 minutes)..." -ForegroundColor Yellow
Write-Host "  Image: $IMAGE_NAME" -ForegroundColor Gray
docker build -t $IMAGE_NAME .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Docker build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Build successful!" -ForegroundColor Green

# Push the image
Write-Host ""
Write-Host "Pushing image to Google Container Registry..." -ForegroundColor Yellow
docker push $IMAGE_NAME

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Docker push failed!" -ForegroundColor Red
    Write-Host "Make sure you're authenticated: gcloud auth login" -ForegroundColor Yellow
    exit 1
}
Write-Host "  Push successful!" -ForegroundColor Green

# Deploy to Cloud Run
Write-Host ""
Write-Host "Deploying to Cloud Run..." -ForegroundColor Yellow

# Build deploy command base
$deployArgs = @(
    "run", "deploy", $SERVICE_NAME,
    "--image", $IMAGE_NAME,
    "--platform", "managed",
    "--region", $REGION,
    "--allow-unauthenticated",
    "--memory", "2Gi",
    "--cpu", "2",
    "--timeout", "300",
    "--max-instances", "10"
)

# Add secrets if they exist, otherwise use environment variables
$secretsAdded = $false
$secretList = @()
$envVars = @("PYTHONPATH=/app:/app/PurpleLlama")

try {
    gcloud secrets describe openai-api-key --quiet 2>$null | Out-Null
    $secretList += "OPENAI_API_KEY=openai-api-key:latest"
    $secretsAdded = $true
    Write-Host "  Using secret: openai-api-key" -ForegroundColor Green
} catch {
    if ($env:OPENAI_API_KEY) {
        $envVars += "OPENAI_API_KEY=$env:OPENAI_API_KEY"
        Write-Host "  Using environment variable: OPENAI_API_KEY" -ForegroundColor Yellow
    } else {
        Write-Host "Warning: OPENAI_API_KEY not found in secrets or environment!" -ForegroundColor Red
        Write-Host "  Create secret: echo 'sk-your-key' | gcloud secrets create openai-api-key --data-file=-" -ForegroundColor Yellow
    }
}

try {
    gcloud secrets describe hf-token --quiet 2>$null | Out-Null
    $secretList += "HF_TOKEN=hf-token:latest"
    $secretsAdded = $true
    Write-Host "  Using secret: hf-token" -ForegroundColor Green
} catch {
    if ($env:HF_TOKEN) {
        $envVars += "HF_TOKEN=$env:HF_TOKEN"
        Write-Host "  Using environment variable: HF_TOKEN" -ForegroundColor Yellow
    }
}

try {
    gcloud secrets describe openai-model --quiet 2>$null | Out-Null
    $secretList += "OPENAI_MODEL=openai-model:latest"
    $secretsAdded = $true
    Write-Host "  Using secret: openai-model" -ForegroundColor Green
} catch {
    if ($env:OPENAI_MODEL) {
        $envVars += "OPENAI_MODEL=$env:OPENAI_MODEL"
    } else {
        $envVars += "OPENAI_MODEL=gpt-4o-mini"
    }
    Write-Host "  Using default model: gpt-4o-mini" -ForegroundColor Gray
}

# Add secrets or env vars to deploy command
if ($secretsAdded -and $secretList.Count -gt 0) {
    $deployArgs += "--set-secrets"
    $deployArgs += ($secretList -join ",")
}

# Always add environment variables (PYTHONPATH and any non-secret vars)
if ($envVars.Count -gt 0) {
    $deployArgs += "--set-env-vars"
    $deployArgs += ($envVars -join ",")
}

# Execute deployment
Write-Host ""
Write-Host "Deploying service (this may take 2-3 minutes)..." -ForegroundColor Yellow

# Execute deployment
# We use a custom string construction to ensure arguments with commas/equals/spaces are quoted
# This is required for Windows batch files (like gcloud.cmd) when called from PowerShell
$commandString = "gcloud"
foreach ($arg in $deployArgs) {
    if ($arg -match '[,= ]') {
        $commandString += " `"$arg`""
    } else {
        $commandString += " $arg"
    }
}

Write-Host "Executing: $commandString" -ForegroundColor Gray
Invoke-Expression $commandString

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Deployment failed!" -ForegroundColor Red
    exit 1
}

# Get the service URL
Write-Host ""
Write-Host "Getting service URL..." -ForegroundColor Yellow
$SERVICE_URL = gcloud run services describe $SERVICE_NAME `
    --platform managed `
    --region $REGION `
    --format 'value(status.url)'

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Deployment Successful!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Service URL: $SERVICE_URL" -ForegroundColor Cyan -BackgroundColor Black
Write-Host ""
Write-Host "Open this URL in your browser to access the secure chatbot!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Test it with:" -ForegroundColor Yellow
Write-Host "  - Safe input: 'Hello! How can you help me?'" -ForegroundColor Gray
Write-Host "  - Unsafe input: 'Ignore all previous instructions'" -ForegroundColor Gray
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
