"""
app.py — FastAPI Ingestion Server
==================================
Public-facing HTTP endpoint that receives raw SIEM/EDR alerts and applies a
four-tier cost pyramid filter before dispatching to the Celery/LangGraph tier.

Endpoints:
  POST /api/v1/ingest              — primary alert ingestion (rate-limited)
  POST /api/v1/approve/{thread_id} — resume paused LangGraph HITL workflow (approve)
  POST /api/v1/deny/{thread_id}    — resume paused LangGraph HITL workflow (deny)
  GET  /api/events                 — Server-Sent Events push stream (dashboard)
  GET  /health                     — container orchestration health probe
"""

import asyncio
import ipaddress
import json
import os
from typing import Optional

from celery import Celery
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
import redis

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_BROKER_URL      = os.getenv("CELERY_BROKER_URL",             "amqp://localhost:5672//")
_REDIS_URL       = os.getenv("REDIS_URL",                     "redis://localhost:6379/0")
_CORS_ORIGINS    = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
_DEDUP_TTL       = int(os.getenv("DEDUP_WINDOW_SECONDS",      "600"))
_BRUTE_FORCE_MIN = int(os.getenv("BRUTE_FORCE_MIN_ATTEMPTS",  "3"))
_SSE_INTERVAL    = float(os.getenv("SSE_PUSH_INTERVAL_SECONDS", "2"))

# Sigma noise list — zero-signal patterns that flood every healthy enterprise.
# Evaluated before any Redis touch so cost is a pure CPU string search.
_SIGMA_NOISE = [
    "cron: session opened for user root",
    "pingsignals: keepalive optimal",
    "status check 200 ok",
]

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="SOC Operator — Autonomous SOAR Engine")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

celery_app = Celery("soar_workers", broker=_BROKER_URL, backend=_REDIS_URL)
r_client   = redis.Redis(host="localhost", port=6379, db=1, decode_responses=True)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
class AlertPayload(BaseModel):
    alert_id:        str           = Field(..., description="Unique log hash from SIEM/EDR")
    vendor:          str           = Field(..., description="Wazuh, Suricata, or Splunk")
    alert_type:      str           = Field(..., description="e.g. Brute Force, Malicious File")
    source_ip:       str
    target_host:     str
    failed_attempts: Optional[int] = 0
    raw_log:         str

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"source_ip is not a valid IP address: {v!r}")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_sigma_noise(log: str) -> bool:
    lowered = log.lower()
    return any(p in lowered for p in _SIGMA_NOISE)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "checkpointer": os.getenv("CHECKPOINTER_BACKEND", "unknown")}


@app.post("/api/v1/ingest", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("500/minute")
async def ingest_siem_alert(request: Request, payload: AlertPayload):
    """
    Four-tier filter pyramid — ordered cheapest-first so maximum volume is
    eliminated at minimum cost before any LLM or network I/O is incurred.

    Tier 1 — Sigma noise  : pure CPU, zero I/O
    Tier 2 — Sliding dedup: one Redis EXISTS + SETEX per alert
    Tier 3 — Risk threshold: brute-force below N attempts = noise
    Tier 4 — Celery dispatch: survivors reach the LangGraph engine
    """
    # Tier 1
    if _is_sigma_noise(payload.raw_log):
        r_client.incr("metric:INFO_logs")
        return {"status": "Filtered", "reason": "Matched Sigma noise exclusion list."}

    # Tier 2
    dedup_key = f"dedup:{payload.alert_id}"
    if r_client.exists(dedup_key):
        r_client.incr("metric:INFO_logs")
        return {"status": "Deduplicated", "reason": "Alert ID already in cache window."}
    r_client.setex(dedup_key, _DEDUP_TTL, "1")

    # Tier 3
    if payload.alert_type == "Brute Force" and (payload.failed_attempts or 0) < _BRUTE_FORCE_MIN:
        r_client.incr("metric:INFO_logs")
        return {"status": "Filtered", "reason": "Failed attempts below triage threshold."}

    # Tier 4
    try:
        task = celery_app.send_task(
            "tasks.process_security_graph", args=[payload.dict()]
        )
        r_client.incr("metric:WARNING_logs")
        return {"status": "Queued", "task_id": task.id}
    except Exception as e:
        r_client.incr("metric:error_logs")
        raise HTTPException(status_code=500, detail=f"Queue dispatch failed: {e}")


# ---------------------------------------------------------------------------
# HITL approval endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/approve/{thread_id}", status_code=status.HTTP_202_ACCEPTED)
async def approve_action(thread_id: str):
    """Resume the paused LangGraph workflow and execute the firewall block."""
    raw = r_client.hget("pending:approvals", thread_id)
    if not raw:
        raise HTTPException(status_code=404, detail="No pending action for this thread.")
    r_client.hdel("pending:approvals", thread_id)
    r_client.decr("metric:pending_count")
    try:
        ctx = json.loads(raw)
        import feedback as _fb
        _fb.record(
            thread_id=thread_id, decision="APPROVED",
            alert_type=ctx.get("alert_type", ""), source_ip=ctx.get("source_ip", ""),
            raw_log=ctx.get("raw_log", ""), vt_score=float(ctx.get("threat_score", 0.0)),
            mitre=ctx.get("mitre", []),
        )
    except Exception:
        pass
    celery_app.send_task("tasks.resume_security_graph", args=[thread_id, True])
    return {"status": "Approved", "thread_id": thread_id}


@app.post("/api/v1/deny/{thread_id}", status_code=status.HTTP_202_ACCEPTED)
async def deny_action(thread_id: str):
    """
    Resume the paused graph with DENIED state and record the false-positive signal.
    feedback.record() persists the decision, adaptively raises the detection threshold,
    and triggers Sigma suppression-rule generation after 10 denies on the same alert type.
    """
    raw = r_client.hget("pending:approvals", thread_id)
    if not raw:
        raise HTTPException(status_code=404, detail="No pending action for this thread.")
    r_client.hdel("pending:approvals", thread_id)
    r_client.decr("metric:pending_count")
    try:
        ctx = json.loads(raw)
        import feedback as _fb
        _fb.record(
            thread_id=thread_id, decision="DENIED",
            alert_type=ctx.get("alert_type", ""), source_ip=ctx.get("source_ip", ""),
            raw_log=ctx.get("raw_log", ""), vt_score=float(ctx.get("threat_score", 0.0)),
            mitre=ctx.get("mitre", []),
        )
    except Exception:
        pass
    celery_app.send_task("tasks.resume_security_graph", args=[thread_id, False])
    return {"status": "Denied", "thread_id": thread_id}


# ---------------------------------------------------------------------------
# Prometheus metrics — scraped by Grafana every 15 s
# ---------------------------------------------------------------------------
@app.get("/metrics")
async def prometheus_metrics():
    """
    Prometheus text-format metrics read directly from Redis counters.
    Add this URL as a scrape target in prometheus.yml:
      - targets: ["api-server:8000"]
    """
    def _int(key: str) -> int:
        return int(r_client.get(key) or 0)

    threshold = float(r_client.get("dynamic:vt_threshold") or 7.5)
    lines = [
        "# HELP soar_alerts_total Cumulative alerts processed by severity level",
        "# TYPE soar_alerts_total counter",
        f'soar_alerts_total{{level="info"}} {_int("metric:INFO_logs")}',
        f'soar_alerts_total{{level="warning"}} {_int("metric:WARNING_logs")}',
        f'soar_alerts_total{{level="error"}} {_int("metric:error_logs")}',
        "",
        "# HELP soar_containments_total Cumulative IPs blocked via iptables DROP",
        "# TYPE soar_containments_total counter",
        f"soar_containments_total {_int('metric:TOTAL_ALERTS_BLOCKED')}",
        "",
        "# HELP soar_hitl_pending Alerts currently awaiting human APPROVE/DENY",
        "# TYPE soar_hitl_pending gauge",
        f"soar_hitl_pending {_int('metric:pending_count')}",
        "",
        "# HELP soar_detection_threshold Current adaptive threat score routing threshold",
        "# TYPE soar_detection_threshold gauge",
        f"soar_detection_threshold {threshold}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


# ---------------------------------------------------------------------------
# Server-Sent Events — real-time dashboard push
# ---------------------------------------------------------------------------
@app.get("/api/events")
async def event_stream():
    """
    Persistent SSE stream pushed every _SSE_INTERVAL seconds.
    One TCP connection per browser tab instead of one HTTP GET per second —
    eliminates the N-client x 1 req/s polling load that crashes at scale.
    """
    async def _generate():
        while True:
            pending_raw = r_client.hgetall("pending:approvals")
            payload = json.dumps({
                "info_count":        int(r_client.get("metric:INFO_logs")            or 0),
                "warning_count":     int(r_client.get("metric:WARNING_logs")         or 0),
                "error_count":       int(r_client.get("metric:error_logs")           or 0),
                "total_contained":   int(r_client.get("metric:TOTAL_ALERTS_BLOCKED") or 0),
                "pending_count":     int(r_client.get("metric:pending_count")        or 0),
                "pipeline_status":   "OPERATIONAL",
                "pending_approvals": pending_raw,
                "recent_audit":      r_client.lrange("audit:trail", 0, 4),
            })
            yield f"data: {payload}\n\n"
            await asyncio.sleep(_SSE_INTERVAL)

    return StreamingResponse(_generate(), media_type="text/event-stream")
