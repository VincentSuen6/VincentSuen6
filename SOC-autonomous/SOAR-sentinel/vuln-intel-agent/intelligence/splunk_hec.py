"""
splunk_hec.py — Splunk HTTP Event Collector Client
===================================================
Sends enriched threat records to Splunk via the HTTP Event Collector (HEC).

Setup on your Splunk instance:
  Settings → Data Inputs → HTTP Event Collector → New Token
  Source type: _json | Index: security (or main)

Environment variables:
  SPLUNK_HOST      — Splunk hostname or IP (default: localhost)
  SPLUNK_HEC_PORT  — HEC port (default: 8088)
  SPLUNK_HEC_TOKEN — HEC token from Splunk Settings
  SPLUNK_INDEX     — target index (default: security)
  SPLUNK_SSL       — "true" for HTTPS (default: false for lab use)

Usage:
    from intelligence.splunk_hec import send_to_splunk
    send_to_splunk(enriched_threat_dict)
"""

import os
import json
import time
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

SPLUNK_HOST      = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_HEC_PORT  = int(os.getenv("SPLUNK_HEC_PORT", "8088"))
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX     = os.getenv("SPLUNK_INDEX", "security")
SPLUNK_SSL       = os.getenv("SPLUNK_SSL", "false").lower() == "true"

SCHEME           = "https" if SPLUNK_SSL else "http"
HEC_URL          = f"{SCHEME}://{SPLUNK_HOST}:{SPLUNK_HEC_PORT}/services/collector/event"

HEADERS          = {
    "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
    "Content-Type":  "application/json",
}


def _build_hec_payload(threat: dict) -> dict:
    """Wraps the threat record in Splunk HEC JSON envelope."""
    ts = threat.get("timestamp", "")
    try:
        from datetime import datetime
        epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        epoch = time.time()

    return {
        "time":       epoch,
        "host":       threat.get("agent_name", "unknown"),
        "source":     threat.get("source", "vuln-intel-agent"),
        "sourcetype": f"wazuh:{threat.get('type', 'alert').lower()}",
        "index":      SPLUNK_INDEX,
        "event": {
            # Core threat fields
            "type":            threat.get("type"),
            "rule_id":         threat.get("rule_id"),
            "rule_level":      threat.get("rule_level"),
            "description":     threat.get("description"),
            "agent_name":      threat.get("agent_name"),
            "path":            threat.get("path"),
            "mitre_technique": threat.get("mitre_technique"),
            "mitre_tactic":    threat.get("mitre_tactic"),
            "src_ips":         threat.get("src_ips"),
            "cve_id":          threat.get("cve_id"),
            "risk_score":      threat.get("risk_score", 0),

            # Enrichment summary (top-level for easy Splunk field extraction)
            "abuse_confidence": threat.get("enrichment", {}).get("abuseipdb", {}).get("abuse_confidence_score", 0),
            "vt_malicious":     threat.get("enrichment", {}).get("virustotal_hash", {}).get("malicious", 0),
            "otx_pulses":       threat.get("enrichment", {}).get("otx_ip", {}).get("pulse_count", 0),
            "shodan_open_ports":threat.get("enrichment", {}).get("shodan", {}).get("open_ports", []),
            "misp_hits":        threat.get("enrichment", {}).get("misp_ip", {}).get("misp_hits", 0),

            # Full enrichment blob for dashboards
            "enrichment":      threat.get("enrichment", {}),
        },
    }


def send_to_splunk(threat: dict) -> bool:
    """
    Send a single enriched threat record to Splunk HEC.
    Returns True on success, False on failure (non-fatal).
    """
    if not SPLUNK_HEC_TOKEN:
        print("[Splunk] HEC token not configured — skipping (set SPLUNK_HEC_TOKEN)")
        return False

    payload = _build_hec_payload(threat)

    try:
        r = requests.post(
            HEC_URL,
            headers=HEADERS,
            json=payload,
            timeout=10,
            verify=False,   # self-signed cert in lab — acceptable
        )
        if r.status_code == 200:
            print(f"[Splunk HEC] Sent → index={SPLUNK_INDEX} type={threat.get('type')} risk={threat.get('risk_score',0)}")
            return True
        else:
            print(f"[Splunk HEC] Error {r.status_code}: {r.text[:200]}")
            return False

    except requests.exceptions.ConnectionError:
        print(f"[Splunk HEC] Cannot connect to {HEC_URL} — is Splunk running?")
        return False
    except Exception as e:
        print(f"[Splunk HEC] Unexpected error: {e}")
        return False


def send_batch(threats: list[dict]) -> int:
    """Send multiple events in a single HEC request. Returns count sent."""
    if not SPLUNK_HEC_TOKEN:
        return 0

    # Splunk accepts newline-delimited JSON payloads for batch ingestion
    body = "\n".join(json.dumps(_build_hec_payload(t)) for t in threats)

    try:
        r = requests.post(
            HEC_URL,
            headers=HEADERS,
            data=body,
            timeout=15,
            verify=False,
        )
        if r.status_code == 200:
            print(f"[Splunk HEC] Batch sent: {len(threats)} events")
            return len(threats)
        else:
            print(f"[Splunk HEC] Batch error {r.status_code}: {r.text[:200]}")
            return 0
    except Exception as e:
        print(f"[Splunk HEC] Batch error: {e}")
        return 0


def test_connection() -> bool:
    """Quick connectivity check — useful at startup."""
    if not SPLUNK_HEC_TOKEN:
        return False
    try:
        r = requests.get(
            f"{SCHEME}://{SPLUNK_HOST}:{SPLUNK_HEC_PORT}/services/collector/health",
            headers=HEADERS,
            timeout=5,
            verify=False,
        )
        ok = r.status_code == 200
        print(f"[Splunk HEC] Health check: {'OK' if ok else f'FAILED ({r.status_code})'}")
        return ok
    except Exception:
        print(f"[Splunk HEC] Health check: UNREACHABLE ({HEC_URL})")
        return False
