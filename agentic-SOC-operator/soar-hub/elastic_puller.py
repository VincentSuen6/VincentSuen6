import requests
from requests.auth import HTTPBasicAuth
import time

ELASTIC_URL    = "http://localhost:9201/.internal.alerts-security.alerts-*/_search"
SOAR_WEBHOOK_URL = "http://127.0.0.1:8000/alerts"
AUTH           = HTTPBasicAuth("elastic", "SFU2026")

# Tracks Elasticsearch document IDs already forwarded to prevent reprocessing
# the same alert across consecutive 10-second poll windows.
_seen_ids: set[str] = set()
_MAX_SEEN = 2000   # cap memory — oldest entries implicitly expire via TTL eviction


def poll_and_forward_alerts():
    global _seen_ids
    query = {
        "size": 50,
        "query": {"range": {"@timestamp": {"gte": "now-30s"}}},
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    try:
        response = requests.post(ELASTIC_URL, auth=AUTH, json=query, verify=False, timeout=10)
        if response.status_code != 200:
            print(f"Elasticsearch query failed: {response.status_code}")
            return

        hits = response.json().get("hits", {}).get("hits", [])
        new_alerts = [h for h in hits if h["_id"] not in _seen_ids]

        if not new_alerts:
            return

        for hit in new_alerts:
            alert_id   = hit["_id"]
            alert_data = hit["_source"]
            rule_name  = alert_data.get("kibana.alert.rule.name", "Security Alert")
            print(f" Found Alert [{alert_id[:12]}]: {rule_name}")

            try:
                forward_res = requests.post(SOAR_WEBHOOK_URL, json=alert_data, timeout=30)
                print(f" Forwarded to SOAR Hub. Status: {forward_res.status_code}")
                _seen_ids.add(alert_id)
            except Exception as e:
                print(f" Failed to forward to SOAR Hub: {e}")

        # Trim seen set to prevent unbounded growth
        if len(_seen_ids) > _MAX_SEEN:
            _seen_ids = set(list(_seen_ids)[-_MAX_SEEN:])

    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")


if __name__ == "__main__":
    print("Elastic-to-SOAR Pipeline active. Monitoring port 9201...")
    while True:
        poll_and_forward_alerts()
        time.sleep(10)
