"""
tasks.py — Celery + LangGraph Workflow Engine
=============================================
4-node LangGraph AI graph run as Celery background tasks.
State is checkpointed to PostgreSQL so any worker in the cluster can resume
a paused HITL workflow after the human approves or denies.

Graph flow:
  threat_intel → mitre_map ─[score >= threshold]─► active_containment → splunk_audit → END
                           ─[score <  threshold]─► splunk_audit → END

What changed from the original version:
  Node 1: replaced single VirusTotal call with intel.enrich_ip() — 6-source
          parallel enrichment with composite 0-10 scoring (see intel.py).
  Node 4: replaced Redis circular buffer with audit.append() — Merkle-chained
          tamper-evident PostgreSQL log with PII scrubbing (see audit.py).
  Router: reads threshold dynamically from Redis via feedback.get_threshold()
          instead of a static env var — adjusts without worker restart.
  OTel:   every node emits a trace span to Jaeger. Wall-clock latency per node
          is visible on the Jaeger UI so slow VT calls / Qdrant searches are
          pinpointed instantly rather than discovered in a post-mortem.
"""

import json
import operator
import os
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Annotated, List

import httpx
import redis
from celery import Celery
from langgraph.graph import END, StateGraph
from typing_extensions import TypedDict

import audit
import feedback
import intel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_BROKER_URL     = os.getenv("CELERY_BROKER_URL",        "amqp://localhost:5672//")
_REDIS_URL      = os.getenv("REDIS_URL",                "redis://localhost:6379/0")
_SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL",         "")
_SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN",       "")
_BLOCKED_IP_TTL   = int(os.getenv("BLOCKED_IP_TTL_SECONDS", "86400"))
_POSTGRES_CONN    = os.getenv("POSTGRES_CONN",          "postgresql://soar:soar@localhost:5432/soar")

celery_app = Celery("soar_workers", broker=_BROKER_URL, backend=_REDIS_URL)
r_client   = redis.Redis(host="localhost", port=6379, db=1, decode_responses=True)

_MITRE_MAP: dict[str, tuple[str, str]] = {
    "failed password":      ("T1110.001", "Password Guessing"),
    "brute force":          ("T1110",     "Brute Force"),
    "port scan":            ("T1046",     "Network Service Discovery"),
    "nmap":                 ("T1046",     "Network Service Discovery"),
    "sql injection":        ("T1190",     "Exploit Public-Facing Application"),
    "xss":                  ("T1059.007", "JavaScript"),
    "lateral movement":     ("T1021",     "Remote Services"),
    "exfiltration":         ("T1041",     "Exfiltration Over C2 Channel"),
    "privilege escalation": ("T1068",     "Exploitation for Privilege Escalation"),
}


# ---------------------------------------------------------------------------
# OpenTelemetry — trace each LangGraph node as a child span
# ---------------------------------------------------------------------------
# PROBLEM SOLVED: Without tracing, a slow incident (30s) could be caused by
# VT rate-limiting, a cold Qdrant search, or a stalled Celery worker — and
# you'd have no way to tell which without reading source code and adding prints.
# OTel gives you a Jaeger UI waterfall: Node1=6.2s (VT), Node2=0.1s, Node3=0.3s.
#
# The try/except ensures the pipeline runs normally if Jaeger is unreachable
# (e.g. in CI or local dev without the full Docker stack).
# ---------------------------------------------------------------------------

try:
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    _provider = TracerProvider()
    _provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
            insecure=True,
        ))
    )
    otel_trace.set_tracer_provider(_provider)
    _tracer     = otel_trace.get_tracer("soar.pipeline")
    _OTEL_OK    = True
    print("[OTel] Tracing active — exporting spans to Jaeger.")
except Exception as _otel_err:
    # No-op tracer so every `with tracer.span(...)` call works unchanged.
    class _NoopSpan:
        def set_attribute(self, *a, **kw): pass
        def record_exception(self, *a, **kw): pass
        def set_status(self, *a, **kw): pass

    @contextmanager
    def _noop_ctx(*a, **kw):
        yield _NoopSpan()

    class _NoopTracer:
        def start_as_current_span(self, name, **kw):
            return _noop_ctx()

    _tracer  = _NoopTracer()
    _OTEL_OK = False
    print(f"[OTel] WARNING: tracing disabled ({_otel_err}). Set OTEL_EXPORTER_OTLP_ENDPOINT.")


# ---------------------------------------------------------------------------
# PostgreSQL checkpointer
# ---------------------------------------------------------------------------
try:
    from psycopg_pool import ConnectionPool
    from langgraph.checkpoint.postgres import PostgresSaver

    _pool         = ConnectionPool(conninfo=_POSTGRES_CONN, max_size=20, kwargs={"autocommit": True})
    _checkpointer = PostgresSaver(_pool)
    _checkpointer.setup()
    print(f"[Checkpointer] PostgreSQL connected ({_POSTGRES_CONN.split('@')[-1]})")
except Exception as _cp_err:
    from langgraph.checkpoint.memory import MemorySaver
    _checkpointer = MemorySaver()
    print(f"[Checkpointer] WARNING: PostgreSQL unavailable ({_cp_err}). HITL state is non-durable.")

# Initialise audit + feedback tables (idempotent)
audit.setup()
feedback.setup()


# ---------------------------------------------------------------------------
# State schema
# ---------------------------------------------------------------------------
class AgentState(TypedDict):
    alert_data:          dict
    threat_intel_score:  float
    enrichment:          dict                             # full multi-source detail
    mitre_techniques:    Annotated[List[str], operator.add]
    remediation_action:  str
    audit_trail:         Annotated[List[str], operator.add]


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Node 1: 6-Source Threat Intelligence (replaces single VT call)
# ---------------------------------------------------------------------------
def threat_intel_node(state: AgentState) -> dict:
    """
    Fan out to AbuseIPDB, VirusTotal, OTX, Shodan, MISP in parallel.
    Composite 0-10 score drives the routing decision after Node 2.
    Internal blacklist check is instant (no network) and overrides to 10.0.
    """
    ip = state["alert_data"]["source_ip"]

    with _tracer.start_as_current_span("node.threat_intel") as span:
        span.set_attribute("soar.source_ip",    ip)
        span.set_attribute("soar.alert_type",   state["alert_data"].get("alert_type", ""))
        span.set_attribute("soar.otel_enabled", _OTEL_OK)

        result = intel.enrich_ip(ip)
        score  = result["score"]

        span.set_attribute("soar.composite_score",   score)
        span.set_attribute("soar.active_sources",    str(result.get("active_sources", [])))
        span.set_attribute("soar.blacklist_hit",     result.get("source") == "internal_blacklist")

        note = (
            f"[{_ts()}][Intel] {ip} — score={score:.1f}/10 "
            f"sources={result.get('active_sources', [])} "
            f"({'BLACKLIST' if result.get('source') == 'internal_blacklist' else 'multi-source'})"
        )
        print(note)

    return {
        "threat_intel_score": score,
        "enrichment":         result,
        "audit_trail":        [note],
    }


# ---------------------------------------------------------------------------
# Node 2: MITRE ATT&CK Technique Mapping
# ---------------------------------------------------------------------------
def mitre_map_node(state: AgentState) -> dict:
    raw = state["alert_data"].get("raw_log", "").lower()

    with _tracer.start_as_current_span("node.mitre_map") as span:
        matched = [
            f"{tid} ({name})"
            for kw, (tid, name) in _MITRE_MAP.items()
            if kw in raw
        ]
        if not matched:
            matched = ["T1078 (Valid Accounts — catch-all)"]

        span.set_attribute("soar.mitre_count",      len(matched))
        span.set_attribute("soar.mitre_techniques", str(matched))

    return {
        "mitre_techniques": matched,
        "audit_trail":      [f"[{_ts()}][MITRE] {', '.join(matched)}"],
    }


# ---------------------------------------------------------------------------
# Node 3: Active Containment (HITL-gated via interrupt_before)
# ---------------------------------------------------------------------------
def active_containment_node(state: AgentState) -> dict:
    ip          = state["alert_data"]["source_ip"]
    blocked_key = f"blocked:{ip}"

    with _tracer.start_as_current_span("node.active_containment") as span:
        span.set_attribute("soar.target_ip", ip)

        if r_client.exists(blocked_key):
            span.set_attribute("soar.containment_result", "ALREADY_CONTAINED")
            return {
                "remediation_action": "ALREADY_CONTAINED",
                "audit_trail": [f"[{_ts()}][Containment] {ip} already blocked. Skipped."],
            }

        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            r_client.set(blocked_key, "1", ex=_BLOCKED_IP_TTL)
            r_client.incr("metric:TOTAL_ALERTS_BLOCKED")
            span.set_attribute("soar.containment_result", "CONTAINED_VIA_IPTABLES")
            return {
                "remediation_action": "CONTAINED_VIA_IPTABLES",
                "audit_trail":        [f"[{_ts()}][Containment] iptables DROP applied to {ip}."],
            }
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode(errors="replace") if exc.stderr else "unknown"
            r_client.incr("metric:error_logs")
            span.set_attribute("soar.containment_result", "CONTAINMENT_FAILED")
            span.record_exception(exc)
            return {
                "remediation_action": "CONTAINMENT_FAILED",
                "audit_trail":        [f"[{_ts()}][Containment] iptables failed: {stderr}"],
            }


# ---------------------------------------------------------------------------
# Node 4: Splunk HEC + Merkle-Chained Audit (replaces Redis circular buffer)
# ---------------------------------------------------------------------------
def splunk_audit_node(state: AgentState) -> dict:
    with _tracer.start_as_current_span("node.splunk_audit") as span:
        event = {
            "remediation":  state["remediation_action"],
            "intel_score":  state["threat_intel_score"],
            "enrichment":   state.get("enrichment", {}),
            "mitre":        state["mitre_techniques"],
            "audit_trail":  state["audit_trail"],
        }

        # Splunk HEC POST (optional)
        if _SPLUNK_HEC_URL:
            try:
                with httpx.Client(timeout=3.0) as c:
                    c.post(
                        f"{_SPLUNK_HEC_URL}/services/collector",
                        json={"event": event},
                        headers={"Authorization": f"Splunk {_SPLUNK_HEC_TOKEN}"},
                    )
                span.set_attribute("soar.splunk_sent", True)
            except Exception as e:
                span.set_attribute("soar.splunk_error", str(e))

        # Merkle-chained immutable audit — replaces the mutable Redis LPUSH/LTRIM
        incident_id = state["alert_data"].get("alert_id", "unknown")
        row_hash    = audit.append(incident_id, event)
        span.set_attribute("soar.audit_hash", row_hash or "failed")

    return {"audit_trail": [f"[{_ts()}][Audit] Immutable record committed. hash={row_hash}"]}


# ---------------------------------------------------------------------------
# Conditional router — reads threshold dynamically from Redis
# ---------------------------------------------------------------------------
def _route_by_threat(state: AgentState) -> str:
    """
    Reads the current threshold from Redis on every call.
    feedback.record() adjusts this key when enough DENY decisions accumulate —
    the routing changes immediately without restarting workers.
    """
    threshold = feedback.get_threshold()
    return "contain" if state["threat_intel_score"] >= threshold else "monitor"


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------
workflow = StateGraph(AgentState)
workflow.add_node("threat_intel",       threat_intel_node)
workflow.add_node("mitre_map",          mitre_map_node)
workflow.add_node("active_containment", active_containment_node)
workflow.add_node("splunk_audit",       splunk_audit_node)

workflow.set_entry_point("threat_intel")
workflow.add_edge("threat_intel", "mitre_map")
workflow.add_conditional_edges(
    "mitre_map",
    _route_by_threat,
    {"contain": "active_containment", "monitor": "splunk_audit"},
)
workflow.add_edge("active_containment", "splunk_audit")
workflow.add_edge("splunk_audit", END)

compiled_graph = workflow.compile(
    checkpointer=_checkpointer,
    interrupt_before=["active_containment"],
)


# ---------------------------------------------------------------------------
# Celery task: initial pipeline run
# ---------------------------------------------------------------------------
@celery_app.task(name="tasks.process_security_graph", bind=True, max_retries=3)
def process_security_graph(self, alert_dict: dict) -> None:
    thread_id = f"thread-{alert_dict.get('alert_id', 'unknown')}"
    config    = {"configurable": {"thread_id": thread_id}}

    initial_state: AgentState = {
        "alert_data":         alert_dict,
        "threat_intel_score": 0.0,
        "enrichment":         {},
        "mitre_techniques":   [],
        "remediation_action": "PENDING",
        "audit_trail": [
            f"[{_ts()}][Pipeline] Initialized for {alert_dict.get('target_host', 'unknown')}"
        ],
    }

    try:
        with _tracer.start_as_current_span("pipeline.full_run") as span:
            span.set_attribute("soar.thread_id",   thread_id)
            span.set_attribute("soar.alert_type",  alert_dict.get("alert_type", ""))
            span.set_attribute("soar.source_ip",   alert_dict.get("source_ip", ""))

            compiled_graph.invoke(initial_state, config=config)

            snapshot = compiled_graph.get_state(config)
            if snapshot.next:
                current = snapshot.values
                span.set_attribute("soar.hitl_required", True)
                r_client.hset(
                    "pending:approvals",
                    thread_id,
                    json.dumps({
                        "source_ip":    alert_dict.get("source_ip"),
                        "target_host":  alert_dict.get("target_host"),
                        "alert_type":   alert_dict.get("alert_type"),
                        "threat_score": current.get("threat_intel_score", 0.0),
                        "mitre":        current.get("mitre_techniques", []),
                        "raw_log":      alert_dict.get("raw_log", ""),
                    }),
                )
                r_client.incr("metric:pending_count")

    except Exception as exc:
        r_client.incr("metric:error_logs")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


# ---------------------------------------------------------------------------
# Celery task: resume after human decision
# ---------------------------------------------------------------------------
@celery_app.task(name="tasks.resume_security_graph", bind=True, max_retries=3)
def resume_security_graph(self, thread_id: str, approved: bool) -> None:
    config = {"configurable": {"thread_id": thread_id}}

    try:
        with _tracer.start_as_current_span("pipeline.hitl_resume") as span:
            span.set_attribute("soar.thread_id", thread_id)
            span.set_attribute("soar.approved",  approved)

            if not approved:
                compiled_graph.update_state(
                    config,
                    {
                        "remediation_action": "DENIED_BY_HUMAN",
                        "audit_trail": [f"[{_ts()}][HITL] Containment denied by human operator."],
                    },
                    as_node="active_containment",
                )
            compiled_graph.invoke(None, config=config)

    except Exception as exc:
        r_client.incr("metric:error_logs")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
