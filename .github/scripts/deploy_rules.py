#!/usr/bin/env python3
"""
deploy_rules.py — Detection-as-Code CI/CD deploy script
=========================================================
Reads rules from agentic-SOC-operator/SIEM-Detection/ and pushes them via
REST API to Wazuh, Splunk, and Elastic simultaneously.

Called by .github/workflows/deploy-rules.yml on every push to main that
touches the SIEM-Detection/ tree.

Required GitHub Secrets:
  WAZUH_IP, WAZUH_API_USER, WAZUH_API_PASS
  ELASTIC_IP, ELASTIC_USER, ELASTIC_PASS, KIBANA_IP
  SPLUNK_IP, SPLUNK_REST_USER, SPLUNK_REST_PASS
"""

import os
import sys
import json
import time
import base64
import warnings
import requests
from pathlib import Path

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ── Paths ────────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).parent.parent
RULES_DIR  = REPO_ROOT / "agentic-SOC-operator" / "SIEM-Detection"
WAZUH_DIR  = RULES_DIR / "wazuh"
SPLUNK_DIR = RULES_DIR / "splunk"
ELASTIC_DIR = RULES_DIR / "elastic"  # optional JSON rules

# ── Credentials ──────────────────────────────────────────────────────────────
WAZUH_IP       = os.environ.get("WAZUH_IP", "")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "")

ELASTIC_IP   = os.environ.get("ELASTIC_IP", "")
ELASTIC_USER = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASS = os.environ.get("ELASTIC_PASS", "")
KIBANA_IP    = os.environ.get("KIBANA_IP", "")

SPLUNK_IP        = os.environ.get("SPLUNK_IP", "")
SPLUNK_REST_USER = os.environ.get("SPLUNK_REST_USER", "admin")
SPLUNK_REST_PASS = os.environ.get("SPLUNK_REST_PASS", "")

results: list[str] = []
errors:  list[str] = []


# ── Wazuh ────────────────────────────────────────────────────────────────────

def wazuh_get_token() -> str:
    """Authenticate against the Wazuh API and return a JWT."""
    url = f"https://{WAZUH_IP}:55000/security/user/authenticate"
    r = requests.post(
        url,
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def wazuh_upload_rule(token: str, xml_file: Path) -> bool:
    """Upload a single XML rule file to the Wazuh manager."""
    url = (
        f"https://{WAZUH_IP}:55000/manager/files"
        f"?path=etc/rules/{xml_file.name}&overwrite=true"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/octet-stream",
    }
    r = requests.put(
        url,
        headers=headers,
        data=xml_file.read_bytes(),
        verify=False,
        timeout=15,
    )
    if r.status_code in (200, 201):
        results.append(f"[Wazuh] Uploaded {xml_file.name}")
        return True
    errors.append(f"[Wazuh] Upload failed for {xml_file.name}: {r.status_code} {r.text[:120]}")
    return False


def wazuh_restart(token: str):
    """Restart the Wazuh manager to apply the new rules."""
    url = f"https://{WAZUH_IP}:55000/manager/restart"
    r = requests.put(
        url,
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=15,
    )
    if r.status_code == 200:
        results.append("[Wazuh] Manager restart triggered")
    else:
        errors.append(f"[Wazuh] Restart failed: {r.status_code} {r.text[:120]}")


def deploy_wazuh():
    if not WAZUH_IP or not WAZUH_API_PASS:
        print("[Wazuh] WAZUH_IP / WAZUH_API_PASS not set — skipping")
        return

    xml_files = list(WAZUH_DIR.glob("*.xml"))
    if not xml_files:
        print("[Wazuh] No XML rules found in SIEM-Detection/wazuh/ — skipping")
        return

    print(f"[Wazuh] Deploying {len(xml_files)} rule file(s) to {WAZUH_IP}:55000")
    try:
        token = wazuh_get_token()
    except Exception as e:
        errors.append(f"[Wazuh] Auth failed: {e}")
        return

    uploaded = sum(1 for f in xml_files if wazuh_upload_rule(token, f))
    if uploaded:
        wazuh_restart(token)


# ── Splunk ───────────────────────────────────────────────────────────────────

def splunk_upsert_search(name: str, spl: str, description: str = "") -> bool:
    """Create or update a Splunk saved search via REST API."""
    base_url = f"https://{SPLUNK_IP}:8089"
    session   = requests.Session()
    session.auth    = (SPLUNK_REST_USER, SPLUNK_REST_PASS)
    session.verify  = False

    # Try update first, then create
    for endpoint in (
        f"{base_url}/servicesNS/nobody/search/saved/searches/{requests.utils.quote(name, safe='')}",
        f"{base_url}/servicesNS/nobody/search/saved/searches",
    ):
        payload = {"name": name, "search": spl, "description": description, "output_mode": "json"}
        method  = "POST"
        r = session.request(method, endpoint, data=payload, timeout=15)
        if r.status_code in (200, 201):
            results.append(f"[Splunk] Saved search '{name}' deployed")
            return True
        if r.status_code == 409:
            # Already exists — update
            payload.pop("name", None)
            r2 = session.post(endpoint, data=payload, timeout=15)
            if r2.status_code in (200, 201):
                results.append(f"[Splunk] Saved search '{name}' updated")
                return True

    errors.append(f"[Splunk] Failed to deploy '{name}': {r.status_code} {r.text[:120]}")
    return False


def deploy_splunk():
    if not SPLUNK_IP or not SPLUNK_REST_PASS:
        print("[Splunk] SPLUNK_IP / SPLUNK_REST_PASS not set — skipping")
        return

    spl_files = list(SPLUNK_DIR.glob("*.spl"))
    if not spl_files:
        print("[Splunk] No SPL files found in SIEM-Detection/splunk/ — skipping")
        return

    print(f"[Splunk] Deploying {len(spl_files)} saved search(es) to {SPLUNK_IP}:8089")
    for spl_file in spl_files:
        name = spl_file.stem.replace("_", "-").title()  # e.g. brute_force_detection → Brute-Force-Detection
        spl  = spl_file.read_text(encoding="utf-8").strip()
        splunk_upsert_search(name=f"SOC-{name}", spl=spl, description=f"Auto-deployed from {spl_file.name}")


# ── Elastic / Kibana ─────────────────────────────────────────────────────────

def deploy_elastic():
    """Push JSON detection rules from SIEM-Detection/elastic/ to Kibana."""
    if not KIBANA_IP or not ELASTIC_PASS:
        print("[Elastic] KIBANA_IP / ELASTIC_PASS not set — skipping")
        return

    if not ELASTIC_DIR.exists():
        print("[Elastic] No elastic/ rules directory found — skipping")
        return

    json_files = list(ELASTIC_DIR.glob("*.json"))
    if not json_files:
        print("[Elastic] No JSON rule files in SIEM-Detection/elastic/ — skipping")
        return

    print(f"[Elastic] Deploying {len(json_files)} rule(s) to Kibana at {KIBANA_IP}")
    base_url = f"http://{KIBANA_IP}:5602"
    headers  = {
        "kbn-xsrf":     "true",
        "Content-Type": "application/json",
    }
    auth = (ELASTIC_USER, ELASTIC_PASS)

    for rule_file in json_files:
        try:
            content = json.loads(rule_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"[Elastic] Invalid JSON in {rule_file.name}: {e}")
            continue

        # Support both single rule objects and arrays of rules
        rules = content if isinstance(content, list) else [content]
        print(f"[Elastic] {rule_file.name} → {len(rules)} rule(s)")

        for rule in rules:
            _elastic_upsert_rule(base_url, headers, auth, rule, rule_file.name)


def _elastic_upsert_rule(base_url: str, headers: dict, auth: tuple, rule: dict, filename: str):
    name = rule.get("name", filename)
    r = requests.post(
        f"{base_url}/api/detection_engine/rules",
        headers=headers,
        auth=auth,
        json=rule,
        timeout=15,
    )
    if r.status_code in (200, 201):
        results.append(f"[Elastic] '{name}' deployed")
    elif r.status_code == 409:
        # Conflict: rule_id already exists — update via PUT
        r2 = requests.put(
            f"{base_url}/api/detection_engine/rules",
            headers=headers,
            auth=auth,
            json=rule,
            timeout=15,
        )
        if r2.status_code in (200, 201):
            results.append(f"[Elastic] '{name}' updated")
        else:
            errors.append(f"[Elastic] Update failed for '{name}': {r2.status_code}")
    else:
        errors.append(f"[Elastic] Deploy failed for '{name}': {r.status_code} {r.text[:120]}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Detection-as-Code Deploy Script")
    print(f"  Rules directory: {RULES_DIR}")
    print("=" * 60 + "\n")

    deploy_wazuh()
    deploy_splunk()
    deploy_elastic()

    print("\n── Results ──────────────────────────────────────────────────")
    for msg in results:
        print(f"  OK  {msg}")
    for msg in errors:
        print(f"  ERR {msg}", file=sys.stderr)

    print(f"\n  {len(results)} succeeded | {len(errors)} failed")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
