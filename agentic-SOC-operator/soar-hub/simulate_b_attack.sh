#!/bin/bash
echo "⚡ Simulating High-Confidence Brute-Force Containment Attack..."
echo "----------------------------------------------------"

curl -X POST http://127.0.0.1:8005/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "INC-2026-0530-SSH",
    "vendor": "ElasticAgent",
    "category": "BRUTE_FORCE",
    "src_ip": "185.220.101.5",
    "target_host": "UBUNTU_VM",
    "raw_log": "Failed password for root from 185.220.101.5 port 22 ssh2"
  }'

echo -e "\n----------------------------------------------------"
echo "✅ Telemetry passed to NexusSOAR gateway."
