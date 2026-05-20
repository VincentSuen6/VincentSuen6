import requests
from requests.auth import HTTPBasicAuth
import time
import json

# Point directly to the working Elasticsearch backend port
ELASTIC_URL = "http://localhost:9201/.internal.alerts-security.alerts-*/_search"
SOAR_WEBHOOK_URL = "http://127.0.0.1:8000/alerts"
AUTH = HTTPBasicAuth("elastic", "SFU2026")

def poll_and_forward_alerts():
    # Fetch alerts generated in the last 10 seconds
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-10s"
                }
            }
        }
    }
    
    try:
        # Query Elasticsearch directly
        response = requests.post(ELASTIC_URL, auth=AUTH, json=query, verify=False)
        
        if response.status_code == 200:
            hits = response.json().get('hits', {}).get('hits', [])
            for hit in hits:
                alert_data = hit['_source']
                print(f" Found Alert: {alert_data.get('kibana.alert.rule.name', 'Security Alert')}")
                
                # Forward it immediately to your FastAPI/LangGraph endpoint
                try:
                    forward_res = requests.post(SOAR_WEBHOOK_URL, json=alert_data)
                    print(f"Forwarded to SOAR Hub. Status: {forward_res.status_code}")
                except Exception as e:
                    print(f"Failed to forward to FastAPI: {e}")
        else:
            print(f"Elasticsearch query failed with status code: {response.status_code}")
            
    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")

if __name__ == "__main__":
    print("🚀 Elastic-to-SOAR Pipeline active. Monitoring port 9201...")
    while True:
        poll_and_forward_alerts()
        time.sleep(10)  # Check for new security alerts every 10 seconds
