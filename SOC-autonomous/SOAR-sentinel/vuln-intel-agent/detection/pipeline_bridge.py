"""
pipeline_bridge.py — Detection Layer
=====================================
Tails the Wazuh alert log, filters high-severity events,
and pushes them to GitHub as intelligence/live_threats.json.

On your Ubuntu Wazuh VM:
    sudo python3 detection/pipeline_bridge.py

Wazuh writes new alerts (one JSON object per line) to:
    /var/ossec/logs/alerts/alerts.json

This script tails that file, applies a severity filter (level >= 7),
formats the alert, and pushes it to your GitHub repo so the
Active Response Agent can pick it up.
"""

import json
import os
import sys
import time
import base64
import hashlib
import requests
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
WAZUH_ALERT_LOG = os.getenv(
    "WAZUH_ALERT_LOG", "/var/ossec/logs/alerts/alerts.json"
)
GITHUB_TOKEN    = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO     = os.getenv("GITHUB_REPO", "")          # e.g. "VincentSuen6/vuln-intel-agent"
GITHUB_BRANCH   = os.getenv("GITHUB_BRANCH", "main")
GITHUB_PATH     = "intelligence/live_threats.json"
MIN_LEVEL       = int(os.getenv("MIN_ALERT_LEVEL", "7"))
POLL_INTERVAL   = int(os.getenv("BRIDGE_POLL_INTERVAL", "5"))  # seconds

GITHUB_API      = "https://api.github.com"
HEADERS         = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def classify_alert(alert: dict) -> str:
    """Map a Wazuh alert to a human-readable attack vector tag."""
    rule   = alert.get("rule", {})
    groups = rule.get("groups", [])
    desc   = rule.get("description", "").lower()

    if any(g in groups for g in ["syscheck", "syscheck_file", "syscheck_entry_modified"]):
        return "FILE_TAMPER"
    if "authentication" in desc or "brute" in desc or "ssh" in desc:
        return "BRUTE_FORCE"
    if "web" in desc or "sql" in desc or "injection" in desc:
        return "WEB_ATTACK"
    if "rootkit" in desc or "privilege" in desc:
        return "PRIVILEGE_ESCALATION"
    if "malware" in desc or "virus" in desc:
        return "MALWARE"
    if "network" in desc or "port scan" in desc:
        return "RECON"
    return "UNKNOWN"


def extract_threat(alert: dict) -> dict:
    """Build the standardised threat record from a raw Wazuh alert dict."""
    rule     = alert.get("rule", {})
    syscheck = alert.get("syscheck", {})
    agent    = alert.get("agent", {})
    mitre    = rule.get("mitre", {})

    return {
        "type":            classify_alert(alert),
        "status":          "investigating",
        "timestamp":       alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "rule_id":         rule.get("id", ""),
        "rule_level":      rule.get("level", 0),
        "description":     rule.get("description", ""),
        "agent_name":      agent.get("name", "unknown"),
        "mitre_technique": mitre.get("id", []),
        "mitre_tactic":    mitre.get("tactic", []),
        "path":            syscheck.get("path", ""),
        "changed_attrs":   syscheck.get("changed_attributes", []),
        "perm_after":      syscheck.get("perm_after", ""),
        "raw_log":         json.dumps(alert),
    }


def get_file_sha() -> str | None:
    """Get the current SHA of intelligence/live_threats.json on GitHub."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}"
    r = requests.get(url, headers=HEADERS, params={"ref": GITHUB_BRANCH})
    if r.status_code == 200:
        return r.json().get("sha")
    return None


def push_to_github(threat: dict) -> bool:
    """Create or update live_threats.json on GitHub with the new threat."""
    content  = base64.b64encode(json.dumps(threat, indent=2).encode()).decode()
    sha      = get_file_sha()
    url      = f"{GITHUB_API}/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}"
    payload  = {
        "message": f"Auto-Intel: {threat['type']} detected on {threat['agent_name']}",
        "content": content,
        "branch":  GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(url, headers=HEADERS, json=payload)
    if r.status_code in (200, 201):
        print(f"[Bridge] Pushed to GitHub → {threat['type']} ({threat['description'][:60]})")
        return True
    else:
        print(f"[Bridge] GitHub push failed: {r.status_code} — {r.text[:200]}")
        return False


def tail_alerts(path: str):
    """Generator that yields new JSON lines appended to the Wazuh alert log."""
    with open(path, "r") as f:
        f.seek(0, 2)                    # jump to end of file
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(POLL_INTERVAL)


# ── Main ──────────────────────────────────────────────────────────────────────

def validate_config():
    missing = []
    if not GITHUB_TOKEN:
        missing.append("GITHUB_TOKEN")
    if not GITHUB_REPO:
        missing.append("GITHUB_REPO")
    if missing:
        print(f"[Bridge] ERROR — Missing env vars: {', '.join(missing)}")
        print("         Add them to your .env file and restart.")
        sys.exit(1)


def run():
    validate_config()

    log_path = Path(WAZUH_ALERT_LOG)
    if not log_path.exists():
        print(f"[Bridge] Wazuh alert log not found: {WAZUH_ALERT_LOG}")
        print("         Are you running this on the Wazuh manager VM?")
        print("         Set WAZUH_ALERT_LOG in .env if the path differs.")
        sys.exit(1)

    print(f"[Bridge] Monitoring {WAZUH_ALERT_LOG} (min level: {MIN_LEVEL})")
    print(f"[Bridge] Pushing to github.com/{GITHUB_REPO}/{GITHUB_PATH}")
    print(f"[Bridge] Ctrl+C to stop\n")

    seen_hashes = set()

    for raw_line in tail_alerts(WAZUH_ALERT_LOG):
        try:
            alert = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        level = alert.get("rule", {}).get("level", 0)
        if level < MIN_LEVEL:
            continue

        # Deduplicate within a session (same rule + path)
        dedup_key = hashlib.md5(
            f"{alert.get('rule', {}).get('id')}-{alert.get('syscheck', {}).get('path')}".encode()
        ).hexdigest()
        if dedup_key in seen_hashes:
            continue
        seen_hashes.add(dedup_key)

        threat = extract_threat(alert)
        push_to_github(threat)


if __name__ == "__main__":
    # Demo mode: push the existing live_threats.json directly (for testing on Windows)
    if "--demo" in sys.argv:
        demo_path = Path(__file__).parent.parent / "intelligence" / "live_threats.json"
        if demo_path.exists():
            with open(demo_path) as f:
                threat = json.load(f)
            print("[Bridge DEMO] Pushing existing live_threats.json to GitHub...")
            validate_config()
            push_to_github(threat)
        else:
            print("[Bridge DEMO] No live_threats.json found. Run from project root.")
        sys.exit(0)

    run()
