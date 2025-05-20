#!/bin/bash

# CONFIG
REGION="us-central1"
RUNTIME="python311"
TIME_ZONE="America/New_York"
PROJECT_ID=$(gcloud config get-value project)

declare -A SCHEDULES
SCHEDULES["app-sessions-cleanup"]="0 12 * * *"
SCHEDULES["stripe-cancelled-subscriptions-delete-users"]="0 18 * * *"

cd "$(dirname "$0")/cloud_functions" || exit 1

for dir in */ ; do
    FUNCTION_NAME="${dir%/}"
    echo "Deploying function: $FUNCTION_NAME"

    # Fix timestamps to prevent ZIP error
    find "$FUNCTION_NAME" -exec touch -t 198001010000 {} +

    gcloud functions deploy "$FUNCTION_NAME" \
        --gen2 \
        --runtime="$RUNTIME" \
        --region="$REGION" \
        --source="$FUNCTION_NAME" \
        --entry-point=main \
        --trigger-http \
        --allow-unauthenticated

    DEPLOY_STATUS=$?

    if [ $DEPLOY_STATUS -ne 0 ]; then
        echo "Failed to deploy $FUNCTION_NAME. Skipping scheduler creation."
        continue
    fi

    SCHEDULER_NAME="${FUNCTION_NAME}-job"
    FUNCTION_URL="https://${REGION}-${PROJECT_ID}.cloudfunctions.net/${FUNCTION_NAME}"

    echo "Creating Cloud Scheduler job: $SCHEDULER_NAME"

    SCHEDULE="${SCHEDULES[$FUNCTION_NAME]}"

    if [ -z "$SCHEDULE" ]; then
        echo "No schedule defined for $FUNCTION_NAME. Skipping scheduler job."
        continue
    fi

    gcloud scheduler jobs create http "$SCHEDULER_NAME" \
        --schedule="$SCHEDULE" \
        --time-zone="$TIME_ZONE" \
        --uri="$FUNCTION_URL" \
        --http-method=GET \
        --project="$PROJECT_ID" \
        --location="$REGION" \
        --attempt-deadline=300s \
        --description="Trigger for $FUNCTION_NAME" \
        --quiet \
        --headers="Content-Type=application/json" \
        || echo "Scheduler job $SCHEDULER_NAME may already exist. Skipping."

    echo "$FUNCTION_NAME deployed and scheduled"
done
