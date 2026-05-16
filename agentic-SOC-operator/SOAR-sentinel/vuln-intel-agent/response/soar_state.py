"""
soar_state.py — SOAR LangGraph State Schema
============================================
Shared TypedDict that flows through every node in the SOAR graph.
Covers the full lifecycle: raw alert → triage → intel → remediation → execution.
"""

from typing import TypedDict, List, Dict


class SOCAgentState(TypedDict):
    # ── Input ──────────────────────────────────────────────────────────────────
    raw_alert: dict          # original alert from Wazuh / Elastic / CSPM / Docker

    # ── Node 1: TriageIngestion outputs ────────────────────────────────────────
    threat_category: str     # FILE_TAMPER | BRUTE_FORCE | CLOUD_MISCONFIGURATION | …
    alert_source: str        # wazuh-edr | elastic-siem | cspm | docker/…
    priority: str            # CRITICAL | HIGH | MEDIUM | LOW
    src_ip: str              # primary source IP (empty string if none)
    rule_id: str
    description: str

    # ── Node 2: ThreatIntel outputs ────────────────────────────────────────────
    enrichment_metadata: dict   # AbuseIPDB score, internal blacklist, VT hits, …
    ip_is_malicious: bool
    abuse_score: str            # "0%" – "100%"
    in_internal_blacklist: bool

    # ── Node 3: RemediationArchitect outputs ───────────────────────────────────
    remediation_command: str    # single executable shell command
    remediation_rationale: str  # why this command stops the threat
    requires_claude: bool       # True → escalate to Claude for deep reasoning
    confidence: str             # HIGH | MEDIUM | LOW (deterministic path confidence)

    # ── Execution tracking ─────────────────────────────────────────────────────
    execution_result: dict
    execution_verified: bool

    # ── Claude deep analysis (populated when requires_claude=True) ─────────────
    claude_report: dict

    # ── Audit ──────────────────────────────────────────────────────────────────
    incident_id: str
    audit_logged: bool
    errors: List[str]
