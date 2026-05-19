"""
fastapi_hub.py — HTTP Alert Receiver & SOAR Entry Point
========================================================
Receives webhook alerts from Wazuh integration block and Elastic Security
connector. Normalises each payload, runs it through the enrichment pipeline,
writes to Splunk HEC, pushes to GitHub, and triggers LangGraph SOAR for
high-severity events.

Run on your Ubuntu VM:
    cd agentic-SOC-operator/SOAR-sentinel/vuln-intel-agent
    uvicorn detection.fastapi_hub:app --host 0.0.0.0 --port 8000

Wazuh → add to /var/ossec/etc/ossec.conf:
    <integration>
      <name>custom-fastapi</name>
      <hook_url>http://<THIS_VM_IP>:8000/alerts</hook_url>
      <level>3</level>
      <alert_format>json</alert_format>
    </integration>
    sudo docker restart single-node-wazuh.manager-1

Elastic → Kibana > Stack Management > Connectors > Webhook:
    Method: POST  URL: http://<THIS_VM_IP>:8000/alerts
"""

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

# Make sibling packages importable when uvicorn is launched from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

SOAR_MIN_LEVEL  = int(os.getenv("SOAR_MIN_LEVEL", "9"))
ENRICH_ENABLED  = os.getenv("ENRICH_ENABLED", "true").lower() == "true"
SPLUNK_ENABLED  = os.getenv("SPLUNK_ENABLED", "true").lower() == "true"
GITHUB_TOKEN    = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO     = os.getenv("GITHUB_REPO", "")
CVE_TRIGGER     = os.getenv("CVE_AUTO_TRIGGER", "true").lower() == "true"
SOAR_ENABLED    = os.getenv("SOAR_GRAPH_ENABLED", "true").lower() == "true"

app = FastAPI(title="SOC FastAPI Hub", version="1.0")

# Simple in-memory counter for the /status endpoint
_stats: dict[str, int] = {"received": 0, "processed": 0, "errors": 0}


# ── Alert normalisation ───────────────────────────────────────────────────────

def _is_wazuh(payload: dict) -> bool:
    return "rule" in payload and "agent" in payload


def _is_elastic(payload: dict) -> bool:
    return "alerts" in payload or "kibana.alert.rule.name" in str(payload)


def _normalise_wazuh(payload: dict) -> dict:
    """Convert raw Wazuh integration JSON → internal threat record."""
    from detection.log_orchestrator import build_threat_record, classify_alert
    return build_threat_record(payload, source="wazuh-webhook")


def _normalise_elastic(payload: dict) -> dict:
    """Convert Elastic Security webhook JSON → internal threat record."""
    # Elastic sends either a single alert dict or {"alerts": [...]}
    alerts_list = payload.get("alerts", [payload])
    first = alerts_list[0] if alerts_list else payload

    severity_map = {"low": 4, "medium": 7, "high": 9, "critical": 12}
    sev_str  = str(first.get("kibana.alert.severity", first.get("signal", {}).get("severity", "medium"))).lower()
    sev_int  = severity_map.get(sev_str, 7)

    rule_name = (
        first.get("kibana.alert.rule.name")
        or first.get("signal", {}).get("rule", {}).get("name", "Elastic Detection Rule")
    )

    synthetic_alert = {
        "timestamp": first.get("@timestamp", datetime.now(timezone.utc).isoformat()),
        "rule": {
            "id":          first.get("kibana.alert.rule.uuid", "elastic-rule"),
            "level":       sev_int,
            "description": rule_name,
            "groups":      ["elastic-security"],
            "mitre":       {},
        },
        "agent": {
            "name": first.get("agent", {}).get("name", "elastic-node"),
        },
        "data": {
            "srcip": first.get("source", {}).get("ip", ""),
            "dstip": first.get("destination", {}).get("ip", ""),
        },
        "_source": first,
    }

    from detection.log_orchestrator import build_threat_record
    return build_threat_record(synthetic_alert, source="elastic-webhook")


def normalise(payload: dict) -> dict:
    if _is_wazuh(payload):
        return _normalise_wazuh(payload)
    return _normalise_elastic(payload)


# ── Pipeline execution (runs in background thread) ───────────────────────────

def _run_pipeline(threat: dict):
    try:
        # Step 1 — Enrichment
        if ENRICH_ENABLED:
            from intelligence.enrichment_engine import enrich_threat
            threat = enrich_threat(threat)

        # Step 2 — Splunk HEC
        if SPLUNK_ENABLED:
            from intelligence.splunk_hec import send_to_splunk
            send_to_splunk(threat)

        # Step 3 — GitHub audit ledger
        if GITHUB_TOKEN and GITHUB_REPO:
            from detection.pipeline_bridge import push_to_github
            push_to_github(threat)

        # Step 4 — SOAR graph for high-severity events
        if SOAR_ENABLED and threat.get("rule_level", 0) >= SOAR_MIN_LEVEL:
            from response.soar_graph import run_soar_graph
            threading.Thread(
                target=run_soar_graph,
                args=(threat,),
                daemon=True,
                name=f"soar-{threat.get('type', 'unknown')}",
            ).start()

        # Step 5 — Auto-trigger CVE pipeline if alert names a CVE
        if CVE_TRIGGER and threat.get("cve_id"):
            from main import run_agent
            threading.Thread(
                target=run_agent,
                args=(threat["cve_id"],),
                daemon=True,
                name=f"cve-{threat['cve_id']}",
            ).start()

        _stats["processed"] += 1

    except Exception as e:
        _stats["errors"] += 1
        print(f"[Hub] Pipeline error: {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/alerts", status_code=202)
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    """
    Main ingestion endpoint.
    Accepts Wazuh integration JSON or Elastic Security webhook JSON.
    Returns 202 immediately; processing runs in the background.
    """
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    _stats["received"] += 1

    try:
        threat = normalise(payload)
    except Exception as e:
        _stats["errors"] += 1
        raise HTTPException(status_code=422, detail=f"Normalisation failed: {e}")

    source = threat.get("source", "unknown")
    ttype  = threat.get("type", "UNKNOWN")
    level  = threat.get("rule_level", 0)
    print(f"[Hub] Received {source} alert — {ttype} (level {level})")

    background_tasks.add_task(_run_pipeline, threat)

    return {"status": "accepted", "type": ttype, "source": source, "level": level}


@app.get("/health")
async def health():
    return {"status": "ok", "stats": _stats}


@app.get("/status")
async def status():
    return {
        "pipeline": {
            "enrichment": ENRICH_ENABLED,
            "splunk_hec":  SPLUNK_ENABLED,
            "github":      bool(GITHUB_TOKEN and GITHUB_REPO),
            "soar":        SOAR_ENABLED,
            "cve_trigger": CVE_TRIGGER,
            "soar_min_level": SOAR_MIN_LEVEL,
        },
        "stats": _stats,
    }


@app.post("/test")
async def test_alert(background_tasks: BackgroundTasks):
    """Send a synthetic FILE_TAMPER alert through the full pipeline."""
    synthetic = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": "100100",
            "level": 7,
            "description": "Integrity checksum changed — test alert from FastAPI hub",
            "groups": ["syscheck", "syscheck_entry_modified"],
            "mitre": {"id": ["T1565.001"], "tactic": ["Impact"]},
        },
        "agent": {"name": "test-agent"},
        "syscheck": {"path": "/etc/passwd", "changed_attributes": ["md5", "sha1"]},
        "data": {},
    }
    _stats["received"] += 1
    from detection.log_orchestrator import build_threat_record
    threat = build_threat_record(synthetic, source="test")
    background_tasks.add_task(_run_pipeline, threat)
    return {"status": "test alert queued", "type": "FILE_TAMPER"}
