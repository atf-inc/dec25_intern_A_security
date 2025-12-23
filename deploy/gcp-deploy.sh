#!/bin/bash
# ============================================================================
# GCP Cloud Run Deployment Script for Honeypot Security System
# Run this script from the project root directory
# ============================================================================

set -e

# Configuration - UPDATE THESE VALUES
PROJECT_ID="${GCP_PROJECT_ID:-dec25-intern-a-security}"
REGION="${GCP_REGION:-us-central1}"
REPO_NAME="honeypot-repo"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  GCP Cloud Run Deployment Script${NC}"
echo -e "${CYAN}  Project: ${PROJECT_ID}${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}ERROR: gcloud CLI is not installed.${NC}"
    echo "Please install it from https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Parse arguments
SKIP_SECRETS=false
SKIP_BUILD=false
MONGO_URI=""
GROQ_API_KEY=""
SENDGRID_API_KEY=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --mongo-uri)
            MONGO_URI="$2"
            shift 2
            ;;
        --groq-api-key)
            GROQ_API_KEY="$2"
            shift 2
            ;;
        --sendgrid-api-key)
            SENDGRID_API_KEY="$2"
            shift 2
            ;;
        --skip-secrets)
            SKIP_SECRETS=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

IMAGE_PREFIX="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}"

# Step 1: Set project
echo -e "${YELLOW}[1/8] Setting GCP project to: ${PROJECT_ID}${NC}"
gcloud config set project "${PROJECT_ID}"

# Step 2: Enable required APIs
echo -e "${YELLOW}[2/8] Enabling required GCP APIs...${NC}"
gcloud services enable run.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# Step 3: Create Artifact Registry repository
echo -e "${YELLOW}[3/8] Creating Artifact Registry repository...${NC}"
if ! gcloud artifacts repositories describe ${REPO_NAME} --location=${REGION} &> /dev/null; then
    gcloud artifacts repositories create ${REPO_NAME} \
        --repository-format=docker \
        --location=${REGION} \
        --description="Honeypot Security System Docker images"
    echo -e "${GREEN}  Created ${REPO_NAME}${NC}"
else
    echo -e "${GREEN}  Repository ${REPO_NAME} already exists${NC}"
fi

# Step 4: Configure Docker authentication
echo -e "${YELLOW}[4/8] Configuring Docker authentication...${NC}"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

# Step 5: Store secrets
if [ "$SKIP_SECRETS" = false ]; then
    echo -e "${YELLOW}[5/8] Storing secrets in Secret Manager...${NC}"
    
    if [ -n "$MONGO_URI" ]; then
        if gcloud secrets describe MONGO_URI &> /dev/null; then
            echo -e "${YELLOW}  Updating MONGO_URI secret...${NC}"
            echo -n "$MONGO_URI" | gcloud secrets versions add MONGO_URI --data-file=-
        else
            echo -n "$MONGO_URI" | gcloud secrets create MONGO_URI --data-file=-
        fi
        echo -e "${GREEN}  MONGO_URI secret stored${NC}"
    else
        echo -e "${YELLOW}  WARNING: MONGO_URI not provided. Use --mongo-uri parameter.${NC}"
    fi
    
    if [ -n "$GROQ_API_KEY" ]; then
        if gcloud secrets describe GROQ_API_KEY &> /dev/null; then
            echo -e "${YELLOW}  Updating GROQ_API_KEY secret...${NC}"
            echo -n "$GROQ_API_KEY" | gcloud secrets versions add GROQ_API_KEY --data-file=-
        else
            echo -n "$GROQ_API_KEY" | gcloud secrets create GROQ_API_KEY --data-file=-
        fi
        echo -e "${GREEN}  GROQ_API_KEY secret stored${NC}"
    else
        echo -e "${YELLOW}  WARNING: GROQ_API_KEY not provided. Use --groq-api-key parameter.${NC}"
    fi
    
    if [ -n "$SENDGRID_API_KEY" ]; then
        if gcloud secrets describe SENDGRID_API_KEY &> /dev/null; then
            echo -e "${YELLOW}  Updating SENDGRID_API_KEY secret...${NC}"
            echo -n "$SENDGRID_API_KEY" | gcloud secrets versions add SENDGRID_API_KEY --data-file=-
        else
            echo -n "$SENDGRID_API_KEY" | gcloud secrets create SENDGRID_API_KEY --data-file=-
        fi
        echo -e "${GREEN}  SENDGRID_API_KEY secret stored${NC}"
    else
        echo -e "${CYAN}  INFO: SENDGRID_API_KEY not provided (optional).${NC}"
    fi
else
    echo -e "${YELLOW}[5/8] Skipping secrets setup (--skip-secrets flag set)${NC}"
fi

# Step 6: Build and push Docker images (DVWA and Honeypot first)
if [ "$SKIP_BUILD" = false ]; then
    echo -e "${YELLOW}[6/8] Building and pushing Docker images...${NC}"
    
    # Build DVWA
    echo -e "${CYAN}  Building DVWA image...${NC}"
    cd dvwa
    gcloud builds submit --config=cloudbuild.yaml --timeout=1200
    cd ..
    echo -e "${GREEN}  DVWA image built and pushed${NC}"
    
    # Build Honeypot
    echo -e "${CYAN}  Building Honeypot image (this may take a while due to PyTorch)...${NC}"
    cd honeypot
    gcloud builds submit --config=cloudbuild.yaml --timeout=1800
    cd ..
    echo -e "${GREEN}  Honeypot image built and pushed${NC}"
    
    # Note: Frontend is built AFTER honeypot is deployed to get the correct API URL
    echo -e "${CYAN}  Frontend will be built after honeypot deployment...${NC}"
else
    echo -e "${YELLOW}[6/8] Skipping image build (--skip-build flag set)${NC}"
fi

# Step 7: Deploy to Cloud Run
echo -e "${YELLOW}[7/8] Deploying services to Cloud Run...${NC}"

# Deploy DVWA first
echo -e "${CYAN}  Deploying DVWA...${NC}"
gcloud run deploy dvwa \
    --image "${IMAGE_PREFIX}/dvwa:latest" \
    --platform managed \
    --region ${REGION} \
    --allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 2 \
    --port 8080

DVWA_URL=$(gcloud run services describe dvwa --region=${REGION} --format="value(status.url)")
echo -e "${GREEN}  DVWA deployed at: ${DVWA_URL}${NC}"

# Deploy Honeypot
echo -e "${CYAN}  Deploying Honeypot...${NC}"
gcloud run deploy honeypot \
    --image "${IMAGE_PREFIX}/honeypot:latest" \
    --platform managed \
    --region ${REGION} \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 2 \
    --min-instances 0 \
    --max-instances 5 \
    --port 8080 \
    --timeout 300 \
    --set-secrets "MONGO_URI=MONGO_URI:latest,GROQ_API_KEY=GROQ_API_KEY:latest" \
    --set-env-vars "UPSTREAM_URL=${DVWA_URL},ENABLE_EMAIL_ALERTS=false"

HONEYPOT_URL=$(gcloud run services describe honeypot --region=${REGION} --format="value(status.url)")
echo -e "${GREEN}  Honeypot deployed at: ${HONEYPOT_URL}${NC}"

# Build Frontend with Honeypot URL baked in
if [ "$SKIP_BUILD" = false ]; then
    echo -e "${CYAN}  Building Frontend image with API URL: ${HONEYPOT_URL}...${NC}"
    cd frontend
    gcloud builds submit --config=cloudbuild.yaml \
        --substitutions="_API_URL=${HONEYPOT_URL}" \
        --timeout=1200
    cd ..
    echo -e "${GREEN}  Frontend image built and pushed${NC}"
fi

# Deploy Frontend
echo -e "${CYAN}  Deploying Frontend...${NC}"
gcloud run deploy frontend \
    --image "${IMAGE_PREFIX}/frontend:latest" \
    --platform managed \
    --region ${REGION} \
    --allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 2 \
    --port 8080

FRONTEND_URL=$(gcloud run services describe frontend --region=${REGION} --format="value(status.url)")
echo -e "${GREEN}  Frontend deployed at: ${FRONTEND_URL}${NC}"

# Step 8: Summary
echo ""
echo -e "${GREEN}[8/8] Deployment Complete!${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Service URLs:${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  DVWA (Vulnerable Site):  ${DVWA_URL}"
echo -e "  Honeypot (Backend):      ${HONEYPOT_URL}"
echo -e "  Frontend (Dashboard):    ${FRONTEND_URL}"
echo ""
echo -e "${GREEN}  Access the dashboard at: ${FRONTEND_URL}${NC}"
echo -e "${GREEN}  Traffic to honeypot will be analyzed and routed to DVWA if safe${NC}"
echo ""
echo -e "${YELLOW}  To view logs:${NC}"
echo -e "    gcloud run logs read honeypot --region=${REGION}"
echo ""

