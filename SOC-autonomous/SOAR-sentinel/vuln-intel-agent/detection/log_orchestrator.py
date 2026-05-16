"""
log_orchestrator.py — Python Log Orchestrator
===============================================
Central hub that collects security telemetry from three sources,
routes each event through the Data Enrichment Engine, then sends
enriched events to Splunk HEC and pushes to GitHub as live_threats.json.

Sources
───────
  • Wazuh EDR     — Host FIM / Rootkit / process monitoring
  • Elastic SIEM  — Network / Sysmon events via REST API
  • Docker         — Containerized application logs

Flow
────
  Wazuh ──┐
  Elastic ─┼──► Log Orchestrator ──► Enrichment Engine ──► Splunk HEC
  Docker ──┘                    └──────────────────────► GitHub Ledger
                                                    └──► Claude AI Analyst
                                                         (if CVE present)

On your Ubuntu VM:
    python3 detection/log_orchestrator.py
"""

import json
import os
import sys
import time
import subprocess
import threading
import queue
import hashlib
import requests
import base64
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO       = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH     = os.getenv("GITHUB_BRANCH", "main")
GITHUB_PATH       = "intelligence/live_threats.json"

WAZUH_ALERT_LOG   = os.getenv("WAZUH_ALERT_LOG", "/var/ossec/logs/alerts/alerts.json")
MIN_LEVEL         = int(os.getenv("MIN_ALERT_LEVEL", "7"))

ELASTIC_URL       = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER      = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS      = os.getenv("ELASTIC_PASS", "")
ELASTIC_INDEX     = os.getenv("ELASTIC_INDEX", "winlogbeat-*,filebeat-*")
ELASTIC_POLL      = int(os.getenv("ELASTIC_POLL_INTERVAL", "30"))

DOCKER_CONTAINERS = os.getenv("DOCKER_CONTAINERS", "").split(",")  # csv of container names
DOCKER_POLL       = int(os.getenv("DOCKER_POLL_INTERVAL", "30"))

ENRICH_ENABLED    = os.getenv("ENRICH_ENABLED", "true").lower() == "true"
SPLUNK_ENABLED    = os.getenv("SPLUNK_ENABLED", "true").lower() == "true"
CVE_TRIGGER       = os.getenv("CVE_AUTO_TRIGGER", "true").lower() == "true"

GITHUB_HEADERS    = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
GITHUB_API        = "https://api.github.com"

# Shared queue — all sources feed into this
event_queue: queue.Queue = queue.Queue()

# ── Shared helpers ─────────────────────────────────────────────────────────────

def classify_alert(alert: dict) -> str:
    groups = alert.get("rule", {}).get("groups", [])
    desc   = alert.get("rule", {}).get("description", "").lower()
    src    = alert.get("_source", {})

    if any(g in groups for g in ["syscheck", "syscheck_file"]):
        return "FILE_TAMPER"
    if "brute" in desc or "authentication failure" in desc or "ssh" in desc:
        return "BRUTE_FORCE"
    if "rootkit" in desc or "kernel" in desc:
        return "ROOTKIT"
    if "web" in desc or "sql" in desc or "injection" in desc:
        return "WEB_ATTACK"
    if "privilege" in desc or "escalation" in desc:
        return "PRIVILEGE_ESCALATION"
    if "malware" in desc or "virus" in desc or "trojan" in desc:
        return "MALWARE"
    if "port scan" in desc or "reconnaissance" in desc:
        return "RECON"
    if src.get("event", {}).get("category") == "network":
        return "NETWORK_ANOMALY"
    return "UNKNOWN"


def extract_ips(alert: dict) -> list[str]:
    """Pull any IP addresses out of an alert for enrichment."""
    ips = []
    for field in ["srcip", "dstip", "src_ip", "dst_ip"]:
        v = alert.get("data", {}).get(field) or alert.get("_source", {}).get(field)
        if v and v not in ("127.0.0.1", "::1"):
            ips.append(v)
    return list(set(ips))


def extract_hashes(alert: dict) -> list[str]:
    """Pull file hashes for VirusTotal/OTX enrichment."""
    hashes = []
    syscheck = alert.get("syscheck", {})
    for field in ["md5_after", "sha1_after", "sha256_after", "md5", "sha256"]:
        v = syscheck.get(field) or alert.get("data", {}).get(field)
        if v:
            hashes.append(v)
    return hashes


def extract_cve(alert: dict) -> str | None:
    """Check if the alert references a CVE ID."""
    import re
    text = json.dumps(alert)
    match = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def build_threat_record(alert: dict, source: str) -> dict:
    rule     = alert.get("rule", {})
    syscheck = alert.get("syscheck", {})
    agent    = alert.get("agent", {})
    mitre    = rule.get("mitre", {})
    return {
        "type":            classify_alert(alert),
        "source":          source,
        "status":          "investigating",
        "timestamp":       alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "rule_id":         rule.get("id", ""),
        "rule_level":      rule.get("level", 0),
        "description":     rule.get("description", ""),
        "agent_name":      agent.get("name", source),
        "mitre_technique": mitre.get("id", []),
        "mitre_tactic":    mitre.get("tactic", []),
        "path":            syscheck.get("path", ""),
        "changed_attrs":   syscheck.get("changed_attributes", []),
        "src_ips":         extract_ips(alert),
        "hashes":          extract_hashes(alert),
        "cve_id":          extract_cve(alert),
        "raw_log":         json.dumps(alert),
        "enrichment":      {},
    }


# ── Source 1: Wazuh EDR ───────────────────────────────────────────────────────

def wazuh_source():
    """Tails /var/ossec/logs/alerts/alerts.json and feeds events into the queue."""
    path = Path(WAZUH_ALERT_LOG)
    if not path.exists():
        print(f"[Wazuh] Alert log not found: {WAZUH_ALERT_LOG} — skipping")
        return

    print(f"[Wazuh] Tailing {WAZUH_ALERT_LOG} (min level {MIN_LEVEL})")
    seen = set()

    with open(path) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            level = alert.get("rule", {}).get("level", 0)
            if level < MIN_LEVEL:
                continue

            dedup = hashlib.md5(
                f"{alert.get('rule', {}).get('id')}-{alert.get('id', '')}".encode()
            ).hexdigest()
            if dedup in seen:
                continue
            seen.add(dedup)

            event_queue.put(build_threat_record(alert, "wazuh-edr"))


# ── Source 2: Elastic SIEM ────────────────────────────────────────────────────

def elastic_source():
    """Polls Elastic REST API for recent high-severity Sysmon/network events."""
    if not ELASTIC_URL:
        print("[Elastic] ELASTIC_URL not set — skipping")
        return

    print(f"[Elastic] Polling {ELASTIC_URL}/{ELASTIC_INDEX} every {ELASTIC_POLL}s")
    last_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    auth    = (ELASTIC_USER, ELASTIC_PASS) if ELASTIC_PASS else None

    while True:
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [{"range": {"@timestamp": {"gt": last_ts}}}],
                        "should": [
                            {"match": {"event.category": "process"}},
                            {"match": {"event.category": "network"}},
                            {"match": {"event.category": "file"}},
                            {"range": {"event.severity": {"gte": 3}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }

            r = requests.post(
                f"{ELASTIC_URL}/{ELASTIC_INDEX}/_search",
                json=query,
                auth=auth,
                timeout=10,
            )

            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                for hit in hits:
                    src   = hit.get("_source", {})
                    alert = {
                        "timestamp": src.get("@timestamp", ""),
                        "rule": {
                            "id":          src.get("rule", {}).get("id", "elastic-event"),
                            "level":       src.get("event", {}).get("severity", 7),
                            "description": src.get("message", src.get("event", {}).get("action", "")),
                            "groups":      [src.get("event", {}).get("category", "")],
                            "mitre":       {},
                        },
                        "agent": {"name": src.get("agent", {}).get("name", "elastic-node")},
                        "data":  src,
                        "_source": src,
                    }
                    event_queue.put(build_threat_record(alert, "elastic-siem"))

                if hits:
                    last_ts = hits[0]["_source"].get("@timestamp", last_ts)
                    print(f"[Elastic] Queued {len(hits)} events")
            else:
                print(f"[Elastic] Query failed: {r.status_code}")

        except requests.RequestException as e:
            print(f"[Elastic] Connection error: {e}")

        time.sleep(ELASTIC_POLL)


# ── Source 3: Docker Containers ───────────────────────────────────────────────

DOCKER_KEYWORDS = [
    "error", "exception", "failed", "unauthorized", "forbidden",
    "attack", "inject", "exploit", "overflow", "breach",
]


def docker_source():
    """Polls Docker container logs for security-relevant lines."""
    containers = [c.strip() for c in DOCKER_CONTAINERS if c.strip()]
    if not containers:
        print("[Docker] DOCKER_CONTAINERS not set — skipping")
        return

    print(f"[Docker] Monitoring containers: {containers}")
    last_check: dict[str, str] = {}

    while True:
        for container in containers:
            since = last_check.get(container, "5m")
            try:
                result = subprocess.run(
                    ["docker", "logs", "--since", since, "--timestamps", container],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                lines = (result.stdout + result.stderr).splitlines()
                for line in lines:
                    lower = line.lower()
                    if any(kw in lower for kw in DOCKER_KEYWORDS):
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "rule": {
                                "id":          "docker-log",
                                "level":       7,
                                "description": f"Docker: {line[:120]}",
                                "groups":      ["docker"],
                                "mitre":       {},
                            },
                            "agent": {"name": f"docker/{container}"},
                        }
                        event_queue.put(build_threat_record(alert, f"docker/{container}"))

                last_check[container] = "30s"

            except subprocess.TimeoutExpired:
                pass
            except FileNotFoundError:
                print("[Docker] docker CLI not found — skipping")
                return
            except Exception as e:
                print(f"[Docker] {container}: {e}")

        time.sleep(DOCKER_POLL)


# ── Event processor ────────────────────────────────────────────────────────────

def process_events():
    """
    Reads from the shared queue, runs enrichment, sends to Splunk,
    pushes to GitHub, and optionally triggers the Claude CVE pipeline.
    """
    # Import here to avoid circular deps
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from intelligence.enrichment_engine import enrich_threat
    from intelligence.splunk_hec import send_to_splunk
    from detection.pipeline_bridge import push_to_github

    print("[Orchestrator] Event processor started")

    while True:
        try:
            threat = event_queue.get(timeout=5)

            print(f"\n[Orchestrator] Processing: {threat['type']} from {threat['source']}")

            # Step 1 — Enrich
            if ENRICH_ENABLED:
                threat = enrich_threat(threat)

            # Step 2 — Send to Splunk SIEM
            if SPLUNK_ENABLED:
                send_to_splunk(threat)

            # Step 3 — Push to GitHub (audit ledger + triggers response agent)
            if GITHUB_TOKEN and GITHUB_REPO:
                push_to_github(threat)

            # Step 4 — Auto-trigger CVE pipeline if alert references a CVE
            if CVE_TRIGGER and threat.get("cve_id"):
                cve_id = threat["cve_id"]
                print(f"[Orchestrator] CVE detected: {cve_id} — triggering Claude analyst...")
                threading.Thread(
                    target=_run_cve_pipeline,
                    args=(cve_id,),
                    daemon=True,
                ).start()

            event_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            print(f"[Orchestrator] Processor error: {e}")


def _run_cve_pipeline(cve_id: str):
    """Background thread: runs the full LangGraph CVE intelligence pipeline."""
    try:
        from main import run_agent
        run_agent(cve_id)
    except Exception as e:
        print(f"[Orchestrator] CVE pipeline error for {cve_id}: {e}")


# ── Entry point ────────────────────────────────────────────────────────────────

def run():
    print("=" * 60)
    print("  Python Log Orchestrator — Security Telemetry Hub")
    print("=" * 60)
    print(f"  Sources  : Wazuh EDR | Elastic SIEM | Docker Containers")
    print(f"  Sinks    : Splunk HEC | GitHub Audit Ledger | Claude AI")
    print(f"  Enrich   : {'ON' if ENRICH_ENABLED else 'OFF'}")
    print(f"  Splunk   : {'ON' if SPLUNK_ENABLED else 'OFF'}")
    print("=" * 60 + "\n")

    threads = [
        threading.Thread(target=wazuh_source,  daemon=True, name="wazuh"),
        threading.Thread(target=elastic_source, daemon=True, name="elastic"),
        threading.Thread(target=docker_source,  daemon=True, name="docker"),
        threading.Thread(target=process_events, daemon=True, name="processor"),
    ]

    for t in threads:
        t.start()

    print("[Orchestrator] All source threads started. Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n[Orchestrator] Shutting down.")


if __name__ == "__main__":
    run()
