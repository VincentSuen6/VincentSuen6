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
    incident_id: str

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

    # ── Node 4: MitreMapping outputs ───────────────────────────────────────────
    mitre_tactic: str           # e.g. "Credential Access"
    mitre_tactic_id: str        # e.g. "TA0006"
    mitre_technique: str        # e.g. "T1110.001"
    mitre_technique_name: str   # e.g. "Password Guessing"
    attack_chain: List[str]     # ordered ATT&CK phases observed in this alert

    # ── Node 5: AutonomousContainment outputs ──────────────────────────────────
    execution_result: dict      # subprocess stdout/returncode/success
    execution_verified: bool
    containment_status: str     # CONTAINED | DRY_RUN | BLOCKED | FAILED | ESCALATED
    claude_report: dict         # populated when requires_claude=True

    # ── Node 6: MarkdownSummary outputs ────────────────────────────────────────
    summary_markdown: str       # full executive brief (Markdown)
    notification_sent: bool
    notification_channel: str   # "discord" | "slack" | "both" | "none"

    # ── Audit ──────────────────────────────────────────────────────────────────
    audit_logged: bool
    errors: List[str]
