#!/bin/bash
echo "🔥 Simulating Live Brute-Force Telemetry Ingestion..."
echo "----------------------------------------------------"

curl -X POST http://127.0.0.1:8005/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "DEMO-ATTACK-'$(date +%s)'",
    "vendor": "ElasticAgent",
    "alert_type": "Brute Force",
    "src_ip": "185.220.101.5",
    "target_host": "UBUNTU_VM",
    "raw_log": "Failed password for root from 185.220.101.5 port 22 ssh2"
  }'

echo -e "\n----------------------------------------------------"
echo "✅ Mock telemetry successfully injected into NexusSOAR gateway."
