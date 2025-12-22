#!/bin/bash
# Alternative deployment using local Docker build
# Use this if you don't have IAM permissions

set -e

PROJECT_ID=${GCP_PROJECT_ID:-"dec25-intern-a-security"}
SERVICE_NAME=${SERVICE_NAME:-"quantum-llm-waf-chatbot"}
REGION=${REGION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "Building Docker image locally..."
echo "Project: ${PROJECT_ID}"
echo "Image: ${IMAGE_NAME}"
echo ""

# Check if Docker is running
if ! docker ps &>/dev/null; then
    echo "Error: Docker is not running. Please start Docker."
    exit 1
fi

# Build the Docker image locally
echo "Building Docker image..."
docker build -t ${IMAGE_NAME} .

# Configure Docker for GCR
echo "Configuring Docker for Google Container Registry..."
gcloud auth configure-docker

# Push the image
echo "Pushing image to Google Container Registry..."
docker push ${IMAGE_NAME}

# Deploy to Cloud Run
echo "Deploying to Cloud Run..."

# Build deploy command
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

# Add secrets if they exist
if gcloud secrets describe openai-api-key &>/dev/null; then
    DEPLOY_CMD="${DEPLOY_CMD} --set-secrets OPENAI_API_KEY=openai-api-key:latest"
else
    echo "Warning: openai-api-key secret not found. Using environment variable."
    if [ -n "$OPENAI_API_KEY" ]; then
        DEPLOY_CMD="${DEPLOY_CMD} --set-env-vars OPENAI_API_KEY=${OPENAI_API_KEY}"
    fi
fi

if gcloud secrets describe hf-token &>/dev/null; then
    DEPLOY_CMD="${DEPLOY_CMD},HF_TOKEN=hf-token:latest"
fi

if gcloud secrets describe openai-model &>/dev/null; then
    DEPLOY_CMD="${DEPLOY_CMD},OPENAI_MODEL=openai-model:latest"
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

