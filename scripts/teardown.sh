#!/usr/bin/env bash
# Removes the deployed service and the identities/trust created for it.
# Keeps the BigQuery ATT&CK dataset (needed for local development; costs pennies).
set -u
PROJECT="${PROJECT:-smooth-epsilon-rxjsq}"
REGION=us-central1
echo "This will DELETE in project $PROJECT:"
echo "  Cloud Run service triage-agent, its container repository and source bucket"
echo "  Firestore (default) database  (pending requests and decisions are lost)"
echo "  service accounts triage-agent-sa and ci-deployer, and the GitHub trust pool"
read -r -p 'Type "teardown" to continue: ' ans
[ "$ans" = "teardown" ] || { echo "Cancelled."; exit 1; }

gcloud run services delete triage-agent --region "$REGION" --quiet || true
gcloud artifacts repositories delete cloud-run-source-deploy --location "$REGION" --quiet || true
gcloud storage rm -r "gs://run-sources-$PROJECT-$REGION" --quiet || true
gcloud firestore databases delete --database='(default)' --quiet || true
gcloud iam workload-identity-pools providers delete github-provider --location=global \
  --workload-identity-pool=github-pool --quiet || true
gcloud iam workload-identity-pools delete github-pool --location=global --quiet || true
gcloud iam service-accounts delete "ci-deployer@$PROJECT.iam.gserviceaccount.com" --quiet || true
gcloud iam service-accounts delete "triage-agent-sa@$PROJECT.iam.gserviceaccount.com" --quiet || true
echo "Teardown finished."
