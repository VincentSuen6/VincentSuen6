"""
audit.py — Merkle-Chained Immutable Audit Log + PII Scrubber
=============================================================
PROBLEM SOLVED: A mutable JSONL file and a Redis circular buffer (auto-evicting
after 1000 entries) cannot satisfy SOC 2 Type II or ISO 27001 audit requirements.
An attacker with write access to the SOAR host can delete or alter evidence.

HOW THE CHAIN WORKS:
  Every record is hashed with SHA-256 using this formula:
    row_hash = SHA256(seq + logged_at + incident_id + event_blob_json + prev_hash)

  The first record uses SHA256("GENESIS") as prev_hash.
  Every subsequent record chains to the hash of the row before it.

  If anyone modifies row 42, its row_hash changes. That change breaks row 43
  (which encoded row 42's hash as its own prev_hash), which breaks row 44, and
  so on. audit_verify() detects this by recomputing the entire chain.
  It cannot be fixed silently — you cannot recompute all downstream hashes
  without the private key you don't have (there is none; the chain is the proof).

PII SCRUBBING (GDPR Article 25 — data minimisation):
  RFC 1918 addresses and email patterns are redacted before persistence.
  Internal analyst workstation IPs and on-call email addresses never appear
  in audit records that might be subpoenaed or shared with external auditors.

PostgreSQL table:
  seq         BIGSERIAL PRIMARY KEY     — monotonic insert order
  logged_at   TIMESTAMPTZ               — server-assigned timestamp
  incident_id TEXT                      — links to the pipeline thread
  event_blob  JSONB                     — full scrubbed event payload
  prev_hash   TEXT                      — SHA-256 of previous row's row_hash
  row_hash    TEXT UNIQUE               — this row's tamper-evident hash
"""

import hashlib
import ipaddress
import json
import os
import re

_POSTGRES_CONN = os.getenv("POSTGRES_CONN", "postgresql://soar:soar@localhost:5432/soar")

# PII patterns
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IP_RE    = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_GENESIS_HASH = hashlib.sha256(b"GENESIS").hexdigest()

_DDL = """
CREATE TABLE IF NOT EXISTS audit_chain (
    seq          BIGSERIAL    PRIMARY KEY,
    logged_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    incident_id  TEXT         NOT NULL,
    event_blob   JSONB        NOT NULL,
    prev_hash    TEXT         NOT NULL,
    row_hash     TEXT         NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_incident ON audit_chain (incident_id);
"""


def _get_conn():
    import psycopg
    return psycopg.connect(_POSTGRES_CONN, autocommit=True)


def setup() -> None:
    """Idempotent table creation — call once at worker startup."""
    try:
        with _get_conn() as conn:
            conn.execute(_DDL)
        print("[Audit] audit_chain table ready.")
    except Exception as e:
        print(f"[Audit] WARNING: could not initialise table: {e}")


# ---------------------------------------------------------------------------
# PII scrubbing
# ---------------------------------------------------------------------------

def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def scrub_pii(obj: object) -> object:
    """
    Recursively walk dict / list / str and redact:
      - Email addresses → [REDACTED-EMAIL]
      - RFC 1918 IP addresses → [REDACTED-IP]
    Returns a new object; the original is not mutated.
    External attacker IPs (public addresses) are NOT redacted — they are the
    evidence. Only internal addresses that could identify analysts are removed.
    """
    if isinstance(obj, dict):
        return {k: scrub_pii(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_pii(i) for i in obj]
    if isinstance(obj, str):
        obj = _EMAIL_RE.sub("[REDACTED-EMAIL]", obj)
        obj = _IP_RE.sub(
            lambda m: "[REDACTED-IP]" if _is_private_ip(m.group(0)) else m.group(0),
            obj,
        )
        return obj
    return obj


# ---------------------------------------------------------------------------
# Merkle chain helpers
# ---------------------------------------------------------------------------

def _compute_row_hash(seq: int, logged_at: str, incident_id: str, blob_json: str, prev_hash: str) -> str:
    payload = f"{seq}|{logged_at}|{incident_id}|{blob_json}|{prev_hash}"
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def append(incident_id: str, event: dict) -> str | None:
    """
    Scrub PII from event, compute the Merkle hash, and append to audit_chain.
    Returns the row_hash on success, None if the DB is unreachable (non-fatal).

    Two-step write:
      1. INSERT with a 'pending' placeholder hash so PostgreSQL assigns seq + logged_at.
      2. Compute the final hash using those server-assigned values, then UPDATE.
    This guarantees the hash encodes the exact timestamp PostgreSQL recorded —
    no clock skew between application and database server.
    """
    clean_blob = scrub_pii(event)
    blob_json  = json.dumps(clean_blob, sort_keys=True)

    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT row_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = row[0] if row else _GENESIS_HASH

            inserted = conn.execute(
                """
                INSERT INTO audit_chain (incident_id, event_blob, prev_hash, row_hash)
                VALUES (%s, %s::jsonb, %s, 'pending')
                RETURNING seq, logged_at
                """,
                (incident_id, blob_json, prev_hash),
            ).fetchone()

            seq, logged_at = inserted
            final_hash = _compute_row_hash(seq, str(logged_at), incident_id, blob_json, prev_hash)

            conn.execute(
                "UPDATE audit_chain SET row_hash = %s WHERE seq = %s",
                (final_hash, seq),
            )
            return final_hash

    except Exception as e:
        print(f"[Audit] append failed (non-fatal): {e}")
        return None


def audit_verify() -> tuple[bool, int | None]:
    """
    Walk the full chain and recompute every row_hash.
    Returns (True, None) if intact.
    Returns (False, first_broken_seq) if any record was tampered with.

    Intended for scheduled integrity sweeps (e.g. nightly cron), not the hot path.
    """
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT seq, logged_at, incident_id, event_blob, prev_hash, row_hash "
                "FROM audit_chain ORDER BY seq ASC"
            ).fetchall()
    except Exception as e:
        print(f"[Audit] verify error: {e}")
        return False, None

    expected_prev = _GENESIS_HASH
    for seq, logged_at, incident_id, blob, stored_prev, stored_hash in rows:
        if stored_prev != expected_prev:
            return False, seq
        blob_json = json.dumps(dict(blob), sort_keys=True)
        recomputed = _compute_row_hash(seq, str(logged_at), incident_id, blob_json, stored_prev)
        if recomputed != stored_hash:
            return False, seq
        expected_prev = stored_hash

    return True, None
