#!/bin/bash
# ==============================================================================
# NEXUSSOAR ONE-CLICK ORCHESTRATION BOOTSTRAPPER
# ==============================================================================

echo "========================================="
echo "🛡️  Initializing NexusSOAR Security Stack..."
echo "========================================="

# 1. Step into the Elastic Lab and bring up background datastores
echo "⚡ Step 1: Launching Docker Infrastructure..."
cd /home/vboxuser/VincentSuen6/agentic-SOC-operator/elastic-lab
sudo docker compose up -d

# 2. Return to the application hub
cd /home/vboxuser/VincentSuen6/agentic-SOC-operator/soar-hub

# 3. Clean the pathing environments to kill old project overrides
echo "🧹 Step 2: Resetting Python Execution Paths..."
export PYTHONPATH="."

# 4. Read the production environment variable parameters securely
if [ -f "../.env" ]; then
    echo "🔑 Step 3: Hydrating Pipeline Environment Matrices..."
    export $(grep -v '^#' ../.env | xargs)
else
    echo "⚠️  Warning: No root .env file discovered."
fi

# 5. Initialize the system validation verification check
echo "🧪 Step 4: Running Autonomous Framework Sanity Checks..."
./venv/bin/python test_pipeline.py

# 6. Execute the core API gateway cleanly as an isolated process
echo "🚀 Step 5: Igniting NexusSOAR API Processing Pipeline..."
echo "---------------------------------------------------------"
./venv/bin/python -B -c "import uvicorn; uvicorn.run('main:app', host='127.0.0.1', port=8005, reload=False)"
