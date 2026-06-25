"""
mcp_server.py — SOAR Operator MCP Server
==========================================
Exposes the SOAR engine as a set of Claude-callable MCP tools and resources.

WHY THIS EXISTS:
  Currently in soar_graph.py, Claude receives a static 5-field payload and
  writes a one-shot incident summary. It has no ability to ask follow-up
  questions, cross-reference historical incidents, or look up additional
  context. The result is a shallow summary that misses patterns a human
  analyst would spot immediately.

  With this MCP server, Claude gets the same tools an analyst uses:
    - "Has this IP attacked us before?" → query_audit_chain
    - "What does threat intel say right now?" → enrich_ip
    - "Are there other related alerts pending?" → get_pending_approvals
    - "What CVEs does this host expose?" → enrich_ip (Shodan component)
    - "Approve this one, it looks real" → approve_alert

  Claude goes from reading a summary to conducting an investigation.

TOOLS EXPOSED:
  enrich_ip(ip)                       — 6-source threat intel enrichment
  get_pending_approvals()             — full HITL queue with context
  approve_alert(thread_id, reason)    — approve a pending action
  deny_alert(thread_id, reason)       — deny a pending action (false positive)
  query_audit_chain(incident_id, limit) — Merkle-chained incident history
  search_incidents_by_ip(ip, days)    — all incidents from a given IP
  get_metrics()                       — live pipeline metrics
  trigger_cve_analysis(cve_id)        — fire the 7-node vuln-intel pipeline

RESOURCES EXPOSED:
  soar://metrics     — live pipeline metrics (polled, no subscription needed)
  soar://pending     — current HITL pending approvals

USAGE:
  1. Run standalone:
       python soar/mcp_server.py

  2. Register in Claude Desktop (~/Library/Application Support/Claude/claude_desktop_config.json):
       {
         "mcpServers": {
           "soar-operator": {
             "command": "python",
             "args": ["/path/to/soar/mcp_server.py"],
             "env": {
               "REDIS_HOST": "localhost",
               "POSTGRES_CONN": "postgresql://soar:soar@localhost:5432/soar",
               "SOAR_API_URL": "http://localhost:8000",
               "SOAR_API_KEY": "your-key-here"
             }
           }
         }
       }

  3. Register in Claude Code (.claude/settings.json):
       {
         "mcpServers": {
           "soar-operator": {
             "command": "python",
             "args": ["soar/mcp_server.py"]
           }
         }
       }

  4. Docker: add to docker-compose.yml (see below — runs as SSE MCP server on port 8001)
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import redis
import httpx

# Make soar/ modules importable regardless of working directory
_SOAR_PATH = Path(__file__).parent
if str(_SOAR_PATH) not in sys.path:
    sys.path.insert(0, str(_SOAR_PATH))

# ---------------------------------------------------------------------------
# Config — read from env so this works in Docker and local alike
# ---------------------------------------------------------------------------
_REDIS_HOST      = os.getenv("REDIS_HOST",    "localhost")
_REDIS_PORT      = int(os.getenv("REDIS_PORT", "6379"))
_POSTGRES_CONN   = os.getenv("POSTGRES_CONN", "postgresql://soar:soar@localhost:5432/soar")
_SOAR_API_URL    = os.getenv("SOAR_API_URL",  "http://localhost:8000")
_SOAR_API_KEY    = os.getenv("SOAR_API_KEY",  "")
_TIMEOUT         = 8.0

_r = redis.Redis(host=_REDIS_HOST, port=_REDIS_PORT, db=1, decode_responses=True)


def _soar_headers() -> dict:
    h = {"Content-Type": "application/json"}
    if _SOAR_API_KEY:
        h["X-API-Key"] = _SOAR_API_KEY
    return h


def _pg_conn():
    import psycopg
    return psycopg.connect(_POSTGRES_CONN, autocommit=True)


# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "soar-operator",
    instructions=(
        "You are connected to a live autonomous Security Operations Center (SOC). "
        "You can query threat intelligence, inspect the HITL approval queue, review "
        "the immutable audit chain, and approve or deny containment actions. "
        "Always enrich_ip before approving a containment action. "
        "Always query_audit_chain to check if the IP has been seen before. "
        "Use deny_alert for false positives and include the reason so the feedback "
        "loop can improve the detection threshold."
    ),
)


# ---------------------------------------------------------------------------
# Tool: enrich_ip
# ---------------------------------------------------------------------------
@mcp.tool()
def enrich_ip(ip: str) -> dict:
    """
    Run 6-source parallel threat intelligence enrichment on an IP address.
    Sources: AbuseIPDB, VirusTotal, OTX AlienVault, Shodan, MISP, internal blacklist.
    Returns a composite 0-10 threat score and per-source detail.
    Use this before approving any containment action to verify the threat is real.
    """
    try:
        import intel
        return intel.enrich_ip(ip)
    except Exception as e:
        return {"error": str(e), "score": 0.0, "source": "error"}


# ---------------------------------------------------------------------------
# Tool: get_pending_approvals
# ---------------------------------------------------------------------------
@mcp.tool()
def get_pending_approvals() -> list[dict]:
    """
    Get all HITL (Human-in-the-Loop) alerts currently awaiting approval.
    Each item includes the source IP, target host, threat score, MITRE techniques,
    the raw log that triggered the alert, and the thread_id needed to approve/deny.
    Returns an empty list when nothing is pending.
    """
    raw = _r.hgetall("pending:approvals")
    result = []
    for thread_id, payload_str in raw.items():
        try:
            data = json.loads(payload_str)
            data["thread_id"] = thread_id
            result.append(data)
        except Exception:
            continue
    result.sort(key=lambda x: float(x.get("threat_score", 0)), reverse=True)
    return result


# ---------------------------------------------------------------------------
# Tool: approve_alert
# ---------------------------------------------------------------------------
@mcp.tool()
def approve_alert(thread_id: str, reason: str = "") -> dict:
    """
    Approve a pending HITL alert. This will execute the containment action
    (iptables DROP on the source IP). Use only after verifying with enrich_ip
    and query_audit_chain. The reason parameter is logged for audit purposes.
    Args:
        thread_id: The thread_id from get_pending_approvals()
        reason: Free-text justification for the approval (e.g. "Confirmed TOR exit node with 15 OTX pulses")
    """
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.post(
                f"{_SOAR_API_URL}/api/v1/approve/{thread_id}",
                headers=_soar_headers(),
            )
            if r.status_code == 202:
                if reason:
                    _r.hset("hitl:reasons", thread_id, reason)
                return {"status": "approved", "thread_id": thread_id, "reason": reason}
            return {"status": "error", "http_status": r.status_code, "detail": r.text}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ---------------------------------------------------------------------------
# Tool: deny_alert
# ---------------------------------------------------------------------------
@mcp.tool()
def deny_alert(thread_id: str, reason: str = "") -> dict:
    """
    Deny a pending HITL alert as a false positive. This records the decision
    in the feedback loop, which adaptively raises the detection threshold for
    this alert type after 5 denies. The reason is crucial for improving detection.
    Args:
        thread_id: The thread_id from get_pending_approvals()
        reason: WHY this is a false positive (e.g. "Internal scanner, not an attacker")
    """
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.post(
                f"{_SOAR_API_URL}/api/v1/deny/{thread_id}",
                headers=_soar_headers(),
            )
            if r.status_code == 202:
                if reason:
                    _r.hset("hitl:reasons", thread_id, reason)
                return {"status": "denied", "thread_id": thread_id, "reason": reason}
            return {"status": "error", "http_status": r.status_code, "detail": r.text}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ---------------------------------------------------------------------------
# Tool: query_audit_chain
# ---------------------------------------------------------------------------
@mcp.tool()
def query_audit_chain(incident_id: str = "", limit: int = 20) -> list[dict]:
    """
    Query the Merkle-chained immutable audit log for incident history.
    Use incident_id to filter to a specific incident, or leave blank for
    the most recent N records across all incidents.
    Args:
        incident_id: Filter to a specific incident ID (leave blank for all)
        limit: Maximum number of records to return (default 20, max 100)
    """
    limit = min(limit, 100)
    try:
        with _pg_conn() as conn:
            if incident_id:
                rows = conn.execute(
                    """
                    SELECT seq, logged_at, incident_id, event_blob, row_hash
                    FROM audit_chain
                    WHERE incident_id = %s
                    ORDER BY seq DESC
                    LIMIT %s
                    """,
                    (incident_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT seq, logged_at, incident_id, event_blob, row_hash
                    FROM audit_chain
                    ORDER BY seq DESC
                    LIMIT %s
                    """,
                    (limit,),
                ).fetchall()

            return [
                {
                    "seq":         row[0],
                    "logged_at":   str(row[1]),
                    "incident_id": row[2],
                    "event":       dict(row[3]) if row[3] else {},
                    "row_hash":    row[4][:16] + "...",  # truncate for readability
                }
                for row in rows
            ]
    except Exception as e:
        return [{"error": str(e)}]


# ---------------------------------------------------------------------------
# Tool: search_incidents_by_ip
# ---------------------------------------------------------------------------
@mcp.tool()
def search_incidents_by_ip(ip: str, days: int = 7) -> list[dict]:
    """
    Find all audit chain entries where the source IP matches within a time window.
    Critical for answering: "Has this attacker hit us before?"
    Args:
        ip: Source IP address to search for
        days: How many days back to look (default 7)
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        with _pg_conn() as conn:
            rows = conn.execute(
                """
                SELECT seq, logged_at, incident_id, event_blob->>'intel_score' AS score,
                       event_blob->>'remediation' AS remediation
                FROM audit_chain
                WHERE event_blob::text ILIKE %s
                  AND logged_at >= %s
                ORDER BY seq DESC
                LIMIT 50
                """,
                (f"%{ip}%", cutoff),
            ).fetchall()

            return [
                {
                    "seq":         row[0],
                    "logged_at":   str(row[1]),
                    "incident_id": row[2],
                    "threat_score": row[3],
                    "remediation":  row[4],
                }
                for row in rows
            ]
    except Exception as e:
        return [{"error": str(e)}]


# ---------------------------------------------------------------------------
# Tool: get_metrics
# ---------------------------------------------------------------------------
@mcp.tool()
def get_metrics() -> dict:
    """
    Get current SOAR pipeline metrics from Redis.
    Returns counts for all alert severity levels, containment actions,
    pending HITL approvals, DLQ messages, vuln-intel runs, and the current
    adaptive detection threshold.
    """
    def _int(key: str) -> int:
        return int(_r.get(key) or 0)

    return {
        "alerts": {
            "info_filtered":  _int("metric:INFO_logs"),
            "warning_queued": _int("metric:WARNING_logs"),
            "errors":         _int("metric:error_logs"),
        },
        "containment": {
            "ips_blocked":    _int("metric:TOTAL_ALERTS_BLOCKED"),
            "pending_hitl":   _int("metric:pending_count"),
        },
        "queue": {
            "dlq_messages":   _int("metric:dlq_messages"),
            "clustered_events": _int("metric:clustered_events"),
        },
        "intelligence": {
            "vuln_intel_runs": _int("metric:vuln_intel_runs"),
        },
        "detection_threshold": float(_r.get("dynamic:vt_threshold") or 7.5),
        "blocked_ips": [
            k.removeprefix("blocked:")
            for k in _r.keys("blocked:*")
        ],
    }


# ---------------------------------------------------------------------------
# Tool: trigger_cve_analysis
# ---------------------------------------------------------------------------
@mcp.tool()
def trigger_cve_analysis(cve_id: str) -> dict:
    """
    Trigger the 7-node vuln-intel pipeline for a specific CVE ID.
    The pipeline runs CVE decomposition → OSINT → TAXII/STIX intel →
    cross-validation → MITRE mapping → malware behavior → SIEM rule generation.
    Results (Wazuh XML rule + Splunk SPL query) are written to disk asynchronously.
    Args:
        cve_id: CVE identifier in the format CVE-YYYY-NNNNN (e.g. CVE-2024-1234)
    """
    import re
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id, re.IGNORECASE):
        return {"status": "error", "detail": f"Invalid CVE format: {cve_id!r}"}

    try:
        from celery import Celery
        broker = os.getenv("CELERY_BROKER_URL", "amqp://localhost:5672//")
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        celery_app = Celery("soar_workers", broker=broker, backend=redis_url)
        task = celery_app.send_task("tasks.run_vuln_intel", args=[cve_id.upper()])
        return {
            "status":  "queued",
            "cve_id":  cve_id.upper(),
            "task_id": task.id,
            "note":    "Results written to SOAR-sentinel/vuln-intel-agent/output/ when complete.",
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ---------------------------------------------------------------------------
# Tool: verify_audit_chain_integrity
# ---------------------------------------------------------------------------
@mcp.tool()
def verify_audit_chain_integrity() -> dict:
    """
    Recompute and verify the entire Merkle hash chain in the audit log.
    Returns whether the chain is intact or identifies the first tampered record.
    Use this to confirm no audit records have been modified or deleted.
    This is an expensive operation — runs in O(n) across all audit records.
    """
    try:
        import audit
        intact, broken_seq = audit.audit_verify()
        if intact:
            return {"status": "intact", "tampered_at_seq": None}
        return {"status": "TAMPERED", "tampered_at_seq": broken_seq}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ---------------------------------------------------------------------------
# Resource: soar://metrics
# ---------------------------------------------------------------------------
@mcp.resource("soar://metrics")
def metrics_resource() -> str:
    """Live SOAR pipeline metrics — alert counts, blocked IPs, detection threshold."""
    data = get_metrics()
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Resource: soar://pending
# ---------------------------------------------------------------------------
@mcp.resource("soar://pending")
def pending_resource() -> str:
    """Current HITL pending approvals — full context for each alert awaiting decision."""
    data = get_pending_approvals()
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Resource: soar://blocked-ips/stix
# ---------------------------------------------------------------------------
@mcp.resource("soar://blocked-ips/stix")
def stix_resource() -> str:
    """STIX 2.1 bundle of all confirmed-malicious IPs (internal blacklist + runtime blocks)."""
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.get(
                f"{_SOAR_API_URL}/api/v1/iocs/stix",
                headers=_soar_headers(),
            )
            return r.text
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("[MCP] soar-operator MCP server starting...")
    print(f"[MCP] Redis: {_REDIS_HOST}:{_REDIS_PORT}")
    print(f"[MCP] SOAR API: {_SOAR_API_URL}")
    print(f"[MCP] Tools: enrich_ip, get_pending_approvals, approve_alert, deny_alert,")
    print(f"[MCP]        query_audit_chain, search_incidents_by_ip, get_metrics,")
    print(f"[MCP]        trigger_cve_analysis, verify_audit_chain_integrity")
    mcp.run()
