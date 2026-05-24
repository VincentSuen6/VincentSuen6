"""
feedback.py — HITL Feedback Loop & Adaptive Detection Threshold
===============================================================
PROBLEM SOLVED: Every Deny click is a confirmed false positive. Currently
that signal is discarded. This module captures it, adjusts the scoring
threshold to reduce future false positives, and generates candidate Sigma
suppression rules when a pattern repeats enough to be systematic.

HOW THE ADAPTIVE THRESHOLD WORKS:
  The composite threat score threshold (default 7.5) is stored in Redis under
  the key "dynamic:vt_threshold" so tasks.py reads it dynamically on each
  routing decision — no restart required.

  After every 5 DENY decisions on the same alert_type:
    → threshold rises by +0.5 (e.g. 7.5 → 8.0)
    → future alerts of that type need stronger multi-source corroboration
    → capped at 9.5 so no category becomes permanently unblockable

  After every 10 DENY decisions on the same alert_type:
    → Claude Haiku reads the 10 most recent false-positive raw_log samples
    → generates a Sigma YAML filter rule that EXCLUDES those benign patterns
    → writes it to SIEM-Detection/sigma/candidates/ for human review
    → CI deploys it only after an analyst approves the GitHub PR

WHY NOT AUTO-DEPLOY?
  Sigma rules that are too broad can suppress genuine attacks. The auto-generation
  step saves the analyst 30 minutes of writing YAML. The human-approval step
  before CI deploy ensures a wrong rule can't silently blind your SIEM.

PostgreSQL table: hitl_feedback
  id          BIGSERIAL PRIMARY KEY
  recorded_at TIMESTAMPTZ
  thread_id   TEXT         — links to the LangGraph checkpoint
  decision    TEXT         — 'APPROVED' or 'DENIED'
  alert_type  TEXT         — e.g. 'Brute Force', 'Port Scan'
  source_ip   TEXT
  raw_log     TEXT         — the original log line (for Sigma generation)
  vt_score    FLOAT        — composite score at decision time
  mitre       JSONB        — matched T-codes
"""

import json
import os
from pathlib import Path

import redis

_POSTGRES_CONN       = os.getenv("POSTGRES_CONN",        "postgresql://soar:soar@localhost:5432/soar")
_ANTHROPIC_KEY       = os.getenv("ANTHROPIC_API_KEY",    "")
_SIGMA_CANDIDATES    = Path(__file__).parent.parent / "SIEM-Detection" / "sigma" / "candidates"
_THRESHOLD_KEY       = "dynamic:vt_threshold"
_THRESHOLD_DEFAULT   = float(os.getenv("THREAT_SCORE_THRESHOLD", "7.5"))
_THRESHOLD_MAX       = 9.5
_THRESHOLD_STEP      = 0.5

r_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=1, decode_responses=True
)

_DDL = """
CREATE TABLE IF NOT EXISTS hitl_feedback (
    id          BIGSERIAL    PRIMARY KEY,
    recorded_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    thread_id   TEXT         NOT NULL,
    decision    TEXT         NOT NULL CHECK (decision IN ('APPROVED','DENIED')),
    alert_type  TEXT,
    source_ip   TEXT,
    raw_log     TEXT,
    vt_score    FLOAT,
    mitre       JSONB
);
CREATE INDEX IF NOT EXISTS idx_feedback_type_decision
    ON hitl_feedback (alert_type, decision);
"""


def _get_conn():
    import psycopg
    return psycopg.connect(_POSTGRES_CONN, autocommit=True)


def setup() -> None:
    """Idempotent table creation — call once at startup."""
    try:
        with _get_conn() as conn:
            conn.execute(_DDL)
        print("[Feedback] hitl_feedback table ready.")
    except Exception as e:
        print(f"[Feedback] WARNING: could not initialise table: {e}")


# ---------------------------------------------------------------------------
# Threshold — read dynamically so tasks.py never needs a restart
# ---------------------------------------------------------------------------

def get_threshold() -> float:
    """
    Read the current routing threshold from Redis.
    Falls back to the env default if Redis has no value yet.
    tasks.py calls this on every routing decision so the threshold
    is always the most recently adjusted value.
    """
    raw = r_client.get(_THRESHOLD_KEY)
    return float(raw) if raw else _THRESHOLD_DEFAULT


# ---------------------------------------------------------------------------
# Core recording function
# ---------------------------------------------------------------------------

def record(
    thread_id:  str,
    decision:   str,
    alert_type: str,
    source_ip:  str,
    raw_log:    str,
    vt_score:   float,
    mitre:      list[str],
) -> None:
    """
    Persist the HITL decision and trigger adaptive responses.
    Non-fatal: a DB failure here must never block the pipeline.
    """
    try:
        with _get_conn() as conn:
            conn.execute(
                """
                INSERT INTO hitl_feedback
                    (thread_id, decision, alert_type, source_ip, raw_log, vt_score, mitre)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (thread_id, decision, alert_type, source_ip, raw_log, vt_score, json.dumps(mitre)),
            )
    except Exception as e:
        print(f"[Feedback] record failed (non-fatal): {e}")
        return

    if decision != "DENIED":
        return   # only DENY decisions drive adaptation

    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM hitl_feedback WHERE decision='DENIED' AND alert_type=%s",
                (alert_type,),
            ).fetchone()
            deny_count = int(row[0]) if row else 0
    except Exception:
        return

    # Every 5 denies: raise the threshold to require stronger evidence
    if deny_count > 0 and deny_count % 5 == 0:
        current = get_threshold()
        new_val = min(current + _THRESHOLD_STEP, _THRESHOLD_MAX)
        r_client.set(_THRESHOLD_KEY, str(new_val))
        print(
            f"[Feedback] Threshold {current:.1f} → {new_val:.1f} "
            f"after {deny_count} denies on '{alert_type}'"
        )

    # Every 10 denies: generate a Sigma suppression rule candidate
    if deny_count > 0 and deny_count % 10 == 0:
        _generate_sigma_candidate(alert_type)


# ---------------------------------------------------------------------------
# Sigma rule auto-generation
# ---------------------------------------------------------------------------

def _get_recent_fp_logs(alert_type: str, limit: int = 10) -> list[str]:
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT raw_log FROM hitl_feedback "
                "WHERE decision='DENIED' AND alert_type=%s "
                "ORDER BY recorded_at DESC LIMIT %s",
                (alert_type, limit),
            ).fetchall()
            return [r[0] for r in rows if r[0]]
    except Exception:
        return []


def _generate_sigma_candidate(alert_type: str) -> None:
    """
    Ask Claude Haiku to write a Sigma filter rule that excludes confirmed
    false-positive patterns. Writes YAML to SIEM-Detection/sigma/candidates/
    for human review — NOT auto-deployed to production SIEMs.

    The auto-generate + human-approve pattern saves the analyst ~30 min of
    YAML authoring while preventing a too-broad rule from silently blinding
    the detection engine.
    """
    if not _ANTHROPIC_KEY:
        print("[Feedback] ANTHROPIC_API_KEY not set — skipping Sigma generation.")
        return

    samples = _get_recent_fp_logs(alert_type)
    if not samples:
        return

    sample_text = "\n".join(f"  {i+1}. {log}" for i, log in enumerate(samples))

    prompt = f"""You are a detection engineer writing a Sigma rule to suppress false positives.

These {len(samples)} log lines triggered '{alert_type}' alerts but were confirmed benign by human analysts:

{sample_text}

Write a Sigma YAML detection rule that uses a filter_main condition to EXCLUDE these specific benign patterns
from the '{alert_type}' detection. Use the standard Sigma filter pattern:

detection:
    selection:
        ...existing detection criteria...
    filter_main_<name>:
        ...fields that identify these FP patterns...
    condition: selection and not filter_main_<name>

Rule title: "FP Suppression — {alert_type}"
Return ONLY valid Sigma YAML. No markdown code fences. No explanation text."""

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=_ANTHROPIC_KEY)
        r = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        sigma_yaml = r.content[0].text.strip()

        _SIGMA_CANDIDATES.mkdir(parents=True, exist_ok=True)
        safe_name = alert_type.lower().replace(" ", "_").replace("/", "_")
        out_path  = _SIGMA_CANDIDATES / f"{safe_name}_fp_suppression.yml"
        out_path.write_text(sigma_yaml)

        print(
            f"[Feedback] Sigma candidate → {out_path.name} "
            f"({len(samples)} samples, {len(sigma_yaml)} chars — review before CI deploy)"
        )
    except Exception as e:
        print(f"[Feedback] Sigma generation failed (non-fatal): {e}")
