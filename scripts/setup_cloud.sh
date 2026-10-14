#!/usr/bin/env bash
# Documents the one-time Google Cloud setup for this project.
# NOTE: captured from the commands that were run by hand during Phase 4;
# it has not been re-run end to end as a single script.
set -u
PROJECT="${PROJECT:-smooth-epsilon-rxjsq}"
NUM="${PROJECT_NUMBER:-1044230887700}"
REGION=us-central1
REPO="OmK-security/Alert-Triage-Agent"
RUNTIME_SA="triage-agent-sa@$PROJECT.iam.gserviceaccount.com"
CI_SA="ci-deployer@$PROJECT.iam.gserviceaccount.com"
BUILD_SA="$NUM-compute@developer.gserviceaccount.com"

gcloud config set project "$PROJECT"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  firestore.googleapis.com iamcredentials.googleapis.com sts.googleapis.com serviceusage.googleapis.com \
  aiplatform.googleapis.com bigquery.googleapis.com

# 1. Runtime identity: only what the deployed agent needs
gcloud iam service-accounts create triage-agent-sa --display-name="Alert triage agent runtime"
for role in roles/aiplatform.user roles/bigquery.jobUser roles/bigquery.dataViewer \
            roles/bigquery.connectionUser roles/datastore.user; do
  gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$RUNTIME_SA" --role="$role" --condition=None --quiet >/dev/null
done

# 2. Approval queue store
gcloud firestore databases create --location="$REGION" --type=firestore-native

# 3. Build identity used by source deploys
for role in roles/cloudbuild.builds.builder roles/run.builder roles/artifactregistry.writer roles/storage.objectViewer; do
  gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$BUILD_SA" --role="$role" --condition=None --quiet >/dev/null
done

# 4. CI/CD identity + keyless trust: only pushes to main of this repo may impersonate it
gcloud iam service-accounts create ci-deployer --display-name="GitHub Actions CI/CD"
gcloud iam workload-identity-pools create github-pool --location=global --display-name="GitHub Actions"
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location=global --workload-identity-pool=github-pool \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition="assertion.repository=='$REPO' && assertion.ref=='refs/heads/main'"
gcloud iam service-accounts add-iam-policy-binding "$CI_SA" --quiet >/dev/null \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$NUM/locations/global/workloadIdentityPools/github-pool/attribute.repository/$REPO"
for role in roles/aiplatform.user roles/bigquery.jobUser roles/bigquery.dataViewer roles/bigquery.connectionUser \
            roles/run.admin roles/artifactregistry.writer roles/serviceusage.serviceUsageConsumer; do
  gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$CI_SA" --role="$role" --condition=None --quiet >/dev/null
done
for sa in "$RUNTIME_SA"; do
  gcloud iam service-accounts add-iam-policy-binding "$sa" --member="serviceAccount:$CI_SA" --role=roles/iam.serviceAccountUser --quiet >/dev/null
done
# CI builds the image on the GitHub runner and pushes it to Artifact Registry, so the
# deployer needs no Cloud Build or storage-bucket permissions.
echo "Setup done. Deploy with the command in .github/workflows/ci-cd.yml (Stage 3)."
