"""
elastic_puller.py — Elasticsearch Direct Polling Client
=========================================================
Polls the Elasticsearch REST API (port 9201) every 10 seconds.
Bypasses Kibana entirely — no Node.js overhead, no connector timeouts.

This is the implementation of the architectural pivot described in
agentic-SOC-operator/SIEM-Detection/README.md under "Lessons Learned."

Instead of relying on Kibana's Action Connector to push webhook events
(which silently drops alerts under memory pressure), this script actively
pulls from the Elasticsearch data layer on its own schedule — the same
pattern used by Palo Alto Cortex XSOAR and Splunk SOAR in production.

Flow
----
  Elasticsearch (port 9201)
        │  REST query every 10s
        ▼
  elastic_puller.py   ──► POST /alerts  ──► soar-hub/main.py (FastAPI)
                                                  │
                                                  ▼
                                       LangGraph SOAR graph
                                 (6 nodes: triage → intel → mitre →
                                  remediation → containment → summary)

Run on your Ubuntu VM:
    cd ~/VincentSuen6/agentic-SOC-operator/soar-hub
    source venv/bin/activate
    python3 elastic_puller.py

Environment variables (copy from vuln-intel-agent/.env):
    ELASTIC_URL       — http://localhost:9201
    ELASTIC_USER      — elastic
    ELASTIC_PASS      — your password
    ELASTIC_INDEX     — wazuh-alerts-*,filebeat-*,winlogbeat-*
    ELASTIC_MIN_LEVEL — minimum Wazuh rule level to forward (default: 7)
    SOAR_HUB_URL      — http://localhost:8000  (FastAPI hub)
    POLL_INTERVAL     — seconds between polls (default: 10)
"""

import os
import json
import time
import requests
import warnings
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ── Config ────────────────────────────────────────────────────────────────────
ELASTIC_URL   = os.getenv("ELASTIC_URL", "http://localhost:9201")
ELASTIC_USER  = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS  = os.getenv("ELASTIC_PASS", "")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "wazuh-alerts-*,filebeat-*,winlogbeat-*")
MIN_LEVEL     = int(os.getenv("ELASTIC_MIN_LEVEL", "7"))
SOAR_HUB_URL  = os.getenv("SOAR_HUB_URL", "http://localhost:8000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))

AUTH = (ELASTIC_USER, ELASTIC_PASS) if ELASTIC_PASS else None

# ── Seen-set for deduplication within a session ───────────────────────────────
_seen_ids: set[str] = set()


def _build_query(since_ts: str) -> dict:
    """Build an Elasticsearch DSL query that pulls new high-severity events."""
    return {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gt": since_ts}}}
                ],
                "should": [
                    {"range": {"rule.level": {"gte": MIN_LEVEL}}},
                    {"exists": {"field": "signal.status"}},       # Elastic Security signal
                    {"exists": {"field": "kibana.alert.severity"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "size": 50,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": True,
    }


def _normalise_hit(hit: dict) -> dict:
    """
    Convert a raw Elasticsearch hit into the internal threat record format
    understood by soar-hub/main.py and the SOAR graph.
    Handles both Wazuh-forwarded alerts and native Elastic Security signals.
    """
    src = hit.get("_source", {})
    idx = hit.get("_index", "")

    # ── Wazuh alerts forwarded to Elastic (index: wazuh-alerts-*) ─────────────
    if "wazuh-alerts" in idx or "rule" in src:
        rule     = src.get("rule", {})
        syscheck = src.get("syscheck", {})
        agent    = src.get("agent", {})
        return {
            "source":      "elastic-wazuh-pull",
            "timestamp":   src.get("timestamp", src.get("@timestamp", "")),
            "rule":        rule,
            "agent":       agent,
            "syscheck":    syscheck,
            "data":        src.get("data", {}),
            "rule_id":     rule.get("id", ""),
            "rule_level":  rule.get("level", 0),
            "description": rule.get("description", ""),
            "agent_name":  agent.get("name", "unknown"),
            "src_ips":     [src.get("data", {}).get("srcip", "")] if src.get("data", {}).get("srcip") else [],
        }

    # ── Elastic Security signals / alerts (index: .siem-signals-*) ────────────
    if "signal" in src or "kibana.alert" in str(src):
        signal = src.get("signal", {})
        rule   = signal.get("rule", {})
        severity_map = {"low": 4, "medium": 7, "high": 10, "critical": 14}
        sev = src.get("kibana.alert.severity", signal.get("severity", "medium")).lower()
        return {
            "source":      "elastic-security-pull",
            "timestamp":   src.get("@timestamp", ""),
            "rule": {
                "id":          rule.get("id", "elastic-signal"),
                "level":       severity_map.get(sev, 7),
                "description": rule.get("name", src.get("kibana.alert.rule.name", "")),
                "groups":      ["elastic-security"],
                "mitre":       rule.get("threat", {}),
            },
            "agent":       {"name": src.get("agent", {}).get("name", "elastic-node")},
            "data":        {"srcip": src.get("source", {}).get("ip", "")},
            "rule_level":  severity_map.get(sev, 7),
            "description": rule.get("name", ""),
            "src_ips":     [src.get("source", {}).get("ip", "")] if src.get("source", {}).get("ip") else [],
        }

    # ── Filebeat / generic ECS event ──────────────────────────────────────────
    event = src.get("event", {})
    return {
        "source":      f"elastic-filebeat-pull ({idx})",
        "timestamp":   src.get("@timestamp", ""),
        "rule": {
            "id":          event.get("id", "filebeat-event"),
            "level":       int(event.get("severity", 7)),
            "description": src.get("message", event.get("action", "filebeat event")),
            "groups":      [event.get("category", "")],
            "mitre":       {},
        },
        "agent":       {"name": src.get("agent", {}).get("name", "filebeat")},
        "data":        {"srcip": src.get("source", {}).get("ip", "")},
        "rule_level":  int(event.get("severity", 7)),
        "description": src.get("message", ""),
        "src_ips":     [src.get("source", {}).get("ip", "")] if src.get("source", {}).get("ip") else [],
    }


def _post_to_soar(alert: dict) -> bool:
    """Forward a normalised alert to the FastAPI SOAR hub."""
    try:
        r = requests.post(
            f"{SOAR_HUB_URL}/alerts",
            json=alert,
            timeout=10,
        )
        if r.status_code in (200, 202):
            return True
        print(f"[Puller] SOAR hub rejected alert: {r.status_code} {r.text[:80]}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[Puller] Cannot reach SOAR hub at {SOAR_HUB_URL} — is main.py running?")
        return False
    except Exception as e:
        print(f"[Puller] Unexpected error posting alert: {e}")
        return False


def poll_once(since_ts: str) -> tuple[str, int]:
    """
    Query Elasticsearch for new events since since_ts.
    Returns (new_since_ts, count_forwarded).
    """
    query = _build_query(since_ts)
    try:
        r = requests.post(
            f"{ELASTIC_URL}/{ELASTIC_INDEX}/_search",
            json=query,
            auth=AUTH,
            timeout=15,
            verify=False,
        )
    except requests.exceptions.ConnectionError:
        print(f"[Puller] Cannot connect to Elasticsearch at {ELASTIC_URL}")
        return since_ts, 0
    except Exception as e:
        print(f"[Puller] Query error: {e}")
        return since_ts, 0

    if r.status_code != 200:
        print(f"[Puller] Elasticsearch returned {r.status_code}: {r.text[:120]}")
        return since_ts, 0

    hits  = r.json().get("hits", {}).get("hits", [])
    count = 0

    for hit in hits:
        doc_id = hit.get("_id", "")
        if doc_id in _seen_ids:
            continue
        _seen_ids.add(doc_id)

        alert = _normalise_hit(hit)

        # Only forward events at or above minimum severity
        if alert.get("rule_level", 0) < MIN_LEVEL:
            continue

        src_ts = hit["_source"].get("@timestamp") or hit["_source"].get("timestamp", "")
        if src_ts > since_ts:
            since_ts = src_ts

        if _post_to_soar(alert):
            count += 1
            desc  = alert.get("description", "")[:60]
            level = alert.get("rule_level", 0)
            print(f"[Puller] Forwarded: level={level}  {desc}")

    # Keep seen-set bounded to avoid unbounded memory growth over long sessions
    if len(_seen_ids) > 10_000:
        _seen_ids.clear()

    return since_ts, count


def run():
    print("=" * 60)
    print("  Elastic-to-SOAR Pipeline")
    print(f"  Monitoring: {ELASTIC_URL}/{ELASTIC_INDEX}")
    print(f"  Forwarding: {SOAR_HUB_URL}/alerts")
    print(f"  Min level:  {MIN_LEVEL}  |  Poll interval: {POLL_INTERVAL}s")
    print("=" * 60)
    print()

    # Verify Elasticsearch connectivity before starting loop
    try:
        r = requests.get(f"{ELASTIC_URL}/_cluster/health", auth=AUTH, timeout=10, verify=False)
        status = r.json().get("status", "unknown")
        print(f"[Puller] Elasticsearch cluster health: {status.upper()}")
    except Exception as e:
        print(f"[Puller] WARNING — Cannot reach Elasticsearch: {e}")
        print(f"[Puller] Check that Docker is running and port 9201 is exposed.")
        print(f"[Puller] Continuing anyway (will retry each poll cycle)...\n")

    # Start cursor at current UTC time so we only pull NEW events going forward
    since_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    print(f"[Puller] Cursor start: {since_ts}")
    print(f"[Puller] Elastic-to-SOAR Pipeline active. Monitoring port 9201...\n")

    while True:
        try:
            since_ts, forwarded = poll_once(since_ts)
            if forwarded:
                print(f"[Puller] Poll complete — {forwarded} alert(s) forwarded")
        except KeyboardInterrupt:
            print("\n[Puller] Shutting down.")
            break
        except Exception as e:
            print(f"[Puller] Poll error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
