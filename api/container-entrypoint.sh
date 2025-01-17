#!/bin/sh

# Start the API server
echo "Starting API server..."
poetry run python -m llama_deploy.apiserver &

# Capture the PID of the API server process
API_SERVER_PID=$!

# Wait for the API server to start
sleep 10

# Check if the API server is running
if ! kill -0 $API_SERVER_PID > /dev/null 2>&1; then
    echo "API server failed to start."
    exit 1
fi

# Deploy the workflow
echo "Deploying workflow..."
llamactl deploy ./api/deployment.yml

# Check if the deployment was successful
if [ $? -ne 0 ]; then
    echo "Deployment failed."
    exit 1
fi

echo "Deployment successful."

# Wait for the API server process to finish
wait $API_SERVER_PID
