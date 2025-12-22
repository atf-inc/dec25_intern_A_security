#!/bin/bash
# Deployment script for Google Cloud Run

set -e

# Configuration
PROJECT_ID=${GCP_PROJECT_ID:-"your-project-id"}
SERVICE_NAME=${SERVICE_NAME:-"quantum-llm-waf-chatbot"}
REGION=${REGION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "🚀 Deploying Quantum LLM WAF Secure Chatbot to Google Cloud Run"
echo "Project ID: ${PROJECT_ID}"
echo "Service Name: ${SERVICE_NAME}"
echo "Region: ${REGION}"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI is not installed"
    echo "Install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    echo "Install it from: https://docs.docker.com/get-docker/"
    exit 1
fi

# Set the project
echo "📋 Setting GCP project..."
gcloud config set project ${PROJECT_ID}

# Enable required APIs
echo "🔧 Enabling required APIs..."
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Build and push the Docker image
echo "🐳 Building Docker image..."
gcloud builds submit --tag ${IMAGE_NAME}

# Deploy to Cloud Run
echo "☁️  Deploying to Cloud Run..."

# Build deploy command with secrets if they exist
DEPLOY_CMD="gcloud run deploy ${SERVICE_NAME} \
    --image ${IMAGE_NAME} \
    --platform managed \
    --region ${REGION} \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 2 \
    --timeout 300 \
    --max-instances 10 \
    --set-env-vars PYTHONPATH=/app:/app/PurpleLlama"

# Check if secrets exist and add them
if gcloud secrets describe openai-api-key &>/dev/null; then
    DEPLOY_CMD="${DEPLOY_CMD} --set-secrets OPENAI_API_KEY=openai-api-key:latest"
else
    echo "⚠️  Warning: openai-api-key secret not found. Make sure OPENAI_API_KEY is set in environment."
    if [ -z "$OPENAI_API_KEY" ]; then
        echo "❌ Error: OPENAI_API_KEY not set. Please create the secret or set the environment variable."
        exit 1
    fi
    DEPLOY_CMD="${DEPLOY_CMD} --set-env-vars OPENAI_API_KEY=${OPENAI_API_KEY}"
fi

if gcloud secrets describe hf-token &>/dev/null; then
    DEPLOY_CMD="${DEPLOY_CMD},HF_TOKEN=hf-token:latest"
else
    echo "ℹ️  Info: hf-token secret not found (optional)."
fi

if gcloud secrets describe openai-model &>/dev/null; then
    DEPLOY_CMD="${DEPLOY_CMD},OPENAI_MODEL=openai-model:latest"
else
    echo "ℹ️  Info: openai-model secret not found. Using default (gpt-4o-mini)."
fi

eval $DEPLOY_CMD

# Get the service URL
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
    --platform managed \
    --region ${REGION} \
    --format 'value(status.url)')

echo ""
echo "✅ Deployment successful!"
echo "🌐 Service URL: ${SERVICE_URL}"
echo ""
echo "📝 Note: Make sure to set up secrets in Secret Manager:"
echo "   - openai-api-key"
echo "   - hf-token (optional)"
echo "   - openai-model (optional, defaults to gpt-4o-mini)"
echo ""
echo "To set secrets, run:"
echo "  gcloud secrets create openai-api-key --data-file=-"
echo "  gcloud secrets create hf-token --data-file=-"
echo "  gcloud secrets create openai-model --data-file=-"

