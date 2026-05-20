"""
main.py — SOAR Hub FastAPI Entry Point
=======================================
Receives alert payloads from elastic_puller.py (and optionally from the
Wazuh integration block) and routes each one through the extended 6-node
LangGraph SOAR graph.

Run on your Ubuntu VM (separate terminal from elastic_puller.py):
    cd ~/VincentSuen6/agentic-SOC-operator/soar-hub
    source venv/bin/activate
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Endpoints:
    POST /alerts   — ingest an alert (from elastic_puller or Wazuh integration)
    GET  /health   — liveness check
    GET  /status   — pipeline stats + config summary
    POST /test     — inject a synthetic alert for smoke-testing
"""

import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

# Make the parent project importable from soar-hub/
sys.path.insert(0, str(Path(__file__).parent.parent / "SOAR-sentinel" / "vuln-intel-agent"))

from response.soar_graph import run_soar_graph

app  = FastAPI(title="SOAR Hub", version="2.0")
_stats: dict[str, int] = {"received": 0, "processed": 0, "errors": 0}


def _run(alert: dict):
    try:
        run_soar_graph(alert)
        _stats["processed"] += 1
    except Exception as e:
        _stats["errors"] += 1
        print(f"[Hub] SOAR graph error: {e}")


@app.post("/alerts", status_code=202)
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    """
    Main ingestion endpoint.
    Returns 202 immediately; SOAR graph runs in a background thread.
    """
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    _stats["received"] += 1
    desc  = str(payload.get("description", payload.get("rule", {}).get("description", "")))[:60]
    level = payload.get("rule_level", payload.get("rule", {}).get("level", 0))
    print(f"[Hub] Received alert — level={level}  {desc}")

    background_tasks.add_task(_run, payload)
    return {"status": "accepted", "description": desc, "level": level}


@app.get("/health")
async def health():
    return {"status": "ok", "stats": _stats}


@app.get("/status")
async def status():
    return {
        "soar_graph": "6-node (Triage→Intel→MITRE→Remediation→Containment→Summary)",
        "stats": _stats,
    }


@app.post("/test")
async def test_alert(background_tasks: BackgroundTasks):
    """Inject a synthetic BRUTE_FORCE alert to smoke-test the full pipeline."""
    synthetic = {
        "source": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": "100200",
            "level": 12,
            "description": "SSH brute force: 8+ failed attempts from 45.142.212.100",
            "groups": ["authentication_failed"],
            "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
        },
        "agent": {"name": "test-agent"},
        "data": {"srcip": "45.142.212.100"},
        "rule_level": 12,
        "description": "SSH brute force detected",
        "src_ips": ["45.142.212.100"],
    }
    _stats["received"] += 1
    background_tasks.add_task(_run, synthetic)
    return {"status": "test alert queued", "type": "BRUTE_FORCE", "src_ip": "45.142.212.100"}
