"""
elastic_puller.py — Elasticsearch Alert Polling Daemon
=======================================================
Polls the Elasticsearch alerts index on a configurable interval and forwards
new alerts to the SOAR Hub webhook endpoint.

Configuration via environment variables (all optional, defaults shown):
  ELASTIC_URL          — Elasticsearch alert index URL
  ELASTIC_USER         — basic auth username (default: elastic)
  ELASTIC_PASS         — basic auth password (default: SFU2026)
  SOAR_WEBHOOK_URL     — SOAR Hub /alerts endpoint (default: http://127.0.0.1:8000/alerts)
  POLL_INTERVAL_S      — polling cadence in seconds (default: 10)
  ALERT_LOOKBACK_S     — how far back to query on each poll, in seconds (default: 30)
  MAX_ALERTS_PER_POLL  — maximum hits to process per poll cycle (default: 50)

Why polling over Kibana webhooks:
  Kibana Action Connectors silently fail under memory pressure on single-VM
  labs. Polling the Elasticsearch REST API directly is more resilient and
  mirrors how enterprise SOARs (Cortex XSOAR, Splunk SOAR) ingest alerts.
"""

import os
import time

import requests
from requests.auth import HTTPBasicAuth

_ELASTIC_URL    = os.getenv(
    "ELASTIC_URL",
    "http://localhost:9201/.internal.alerts-security.alerts-*/_search",
)
_SOAR_URL       = os.getenv("SOAR_WEBHOOK_URL", "http://127.0.0.1:8000/alerts")
_USER           = os.getenv("ELASTIC_USER", "elastic")
_PASS           = os.getenv("ELASTIC_PASS", "SFU2026")
_POLL_INTERVAL  = float(os.getenv("POLL_INTERVAL_S",     "10"))
_LOOKBACK_S     = int(os.getenv("ALERT_LOOKBACK_S",       "30"))
_MAX_PER_POLL   = int(os.getenv("MAX_ALERTS_PER_POLL",    "50"))

_AUTH = HTTPBasicAuth(_USER, _PASS)

# Tracks Elasticsearch document IDs already forwarded to prevent reprocessing
# the same alert across consecutive poll windows.
_seen_ids: set[str] = set()
_MAX_SEEN = 2000   # cap memory — oldest entries implicitly expire via TTL eviction


def poll_and_forward_alerts():
    global _seen_ids
    query = {
        "size":  _MAX_PER_POLL,
        "query": {"range": {"@timestamp": {"gte": f"now-{_LOOKBACK_S}s"}}},
        "sort":  [{"@timestamp": {"order": "desc"}}],
    }
    try:
        response = requests.post(
            _ELASTIC_URL, auth=_AUTH, json=query, verify=False, timeout=10
        )
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
                forward_res = requests.post(_SOAR_URL, json=alert_data, timeout=30)
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
    print(
        f"Elastic-to-SOAR Pipeline active. "
        f"Polling every {_POLL_INTERVAL}s (lookback={_LOOKBACK_S}s, max={_MAX_PER_POLL}/poll)..."
    )
    while True:
        poll_and_forward_alerts()
        time.sleep(_POLL_INTERVAL)
