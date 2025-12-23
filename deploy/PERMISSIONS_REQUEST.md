# GCP Permissions Required for Cloud Run Deployment

**Project ID:** `dec25-intern-a-security`  
**Project Number:** `1015557087390`  
**Requested by:** mahathi.s.1504@gmail.com  
**Current Role:** roles/editor

## Issue

The Cloud Build service requires additional IAM permissions to:
1. Upload source code to Cloud Storage
2. Push Docker images to Artifact Registry
3. Deploy services to Cloud Run
4. Access secrets from Secret Manager

## Commands to Run (Requires Project Owner/IAM Admin)

Please run these commands in Google Cloud Shell or a terminal with gcloud authenticated as a Project Owner:

```bash
# Set the project
gcloud config set project dec25-intern-a-security

# 1. Grant Cloud Build service account storage permissions
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="serviceAccount:1015557087390-compute@developer.gserviceaccount.com" \
    --role="roles/storage.objectAdmin"

# 2. Grant Cloud Build service account ability to push to Artifact Registry
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="serviceAccount:1015557087390-compute@developer.gserviceaccount.com" \
    --role="roles/artifactregistry.writer"

# 3. Grant Cloud Build service account ability to deploy to Cloud Run
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="serviceAccount:1015557087390-compute@developer.gserviceaccount.com" \
    --role="roles/run.admin"

# 4. Grant Cloud Build service account ability to access secrets
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="serviceAccount:1015557087390-compute@developer.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

# 5. Grant Cloud Run service account ability to access secrets (for runtime)
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="serviceAccount:1015557087390-compute@developer.gserviceaccount.com" \
    --role="roles/iam.serviceAccountUser"

# 6. Grant the user (mahathi.s.1504@gmail.com) Secret Manager Admin to create secrets
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="user:mahathi.s.1504@gmail.com" \
    --role="roles/secretmanager.admin"

# 7. Grant the user Cloud Run Admin to deploy services
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="user:mahathi.s.1504@gmail.com" \
    --role="roles/run.admin"

# 8. Grant the user ability to act as service accounts
gcloud projects add-iam-policy-binding dec25-intern-a-security \
    --member="user:mahathi.s.1504@gmail.com" \
    --role="roles/iam.serviceAccountUser"
```

## Alternative: Single Command with All Roles

If preferred, all permissions can be granted at once using the Console:

1. Go to: https://console.cloud.google.com/iam-admin/iam?project=dec25-intern-a-security
2. Find `1015557087390-compute@developer.gserviceaccount.com`
3. Click Edit (pencil icon)
4. Add these roles:
   - Storage Object Admin
   - Artifact Registry Writer
   - Cloud Run Admin
   - Secret Manager Secret Accessor
   - Service Account User

5. Find `mahathi.s.1504@gmail.com`
6. Click Edit (pencil icon)
7. Add these roles:
   - Secret Manager Admin
   - Cloud Run Admin
   - Service Account User

## Verification

After permissions are granted, the user can verify with:

```bash
gcloud projects get-iam-policy dec25-intern-a-security \
    --flatten="bindings[].members" \
    --filter="bindings.members:1015557087390-compute@developer.gserviceaccount.com" \
    --format="table(bindings.role)"
```

Expected output should include:
- roles/storage.objectAdmin
- roles/artifactregistry.writer
- roles/run.admin
- roles/secretmanager.secretAccessor
- roles/iam.serviceAccountUser



