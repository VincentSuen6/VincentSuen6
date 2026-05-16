"""
soar_graph.py — LangGraph SOAR State Machine
=============================================
Three-node deterministic LangGraph graph for real-time alert triage,
threat intelligence lookup, and remediation command generation.

Flow
────
  raw_alert
      │
      ▼
  [Node 1] TriageIngestion   — classify alert type, score priority
      │
      ▼
  [Node 2] ThreatIntel       — IP/hash reputation, internal blacklist
      │
      ▼
  [Node 3] RemediationArchitect — deterministic command from allowlist
      │                           or escalates to Claude if needed
      ▼
     END

Standalone usage:
    python response/soar_graph.py --local     # run against intelligence/live_threats.json
    python response/soar_graph.py --demo      # inject synthetic cloud misconfiguration alert

Programmatic usage:
    from response.soar_graph import run_soar_graph
    result = run_soar_graph(threat_dict)
"""

import json
import os
import sys
import time
import platform
import subprocess
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from langgraph.graph import StateGraph, END
from dotenv import load_dotenv

load_dotenv()

# ── Make project root importable when running directly ────────────────────────
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from response.soar_state import SOCAgentState

# ── Config ────────────────────────────────────────────────────────────────────
ANTHROPIC_KEY        = os.getenv("ANTHROPIC_API_KEY", "")
ABUSEIPDB_KEY        = os.getenv("ABUSEIPDB_KEY", "")
DRY_RUN              = os.getenv("DRY_RUN", "true").lower() != "false"
CONFIDENCE_THRESHOLD = float(os.getenv("SOAR_CONFIDENCE_THRESHOLD", "0.92"))

AUDIT_LOG = Path(__file__).parent / "audit_trail.jsonl"

# Known malicious IPs — internal blacklist (supplement with threat feed)
INTERNAL_BLACKLIST = {
    "193.163.125.128",   # known C2 node (recorded from real Wazuh alert)
    "192.168.56.102",    # flagged attacker in lab pivot
    "45.142.212.100",
    "91.108.4.0",
    "185.220.101.0",
}

# Deterministic remediation command map — CATEGORY → command template
REMEDIATION_MAP: dict[str, str] = {
    "FILE_TAMPER":            "chmod 600 {path}",
    "CLOUD_MISCONFIGURATION": "aws s3api put-bucket-acl --bucket {resource_id} --acl private",
    "BRUTE_FORCE":            "fail2ban-client set sshd banip {src_ip}",
    "PRIVILEGE_ESCALATION":   "auditctl -a always,exit -F arch=b64 -S execve -k priv_esc",
    "ROOTKIT":                "systemctl stop suspicious_service || chkrootkit",
    "WEB_ATTACK":             "iptables -A INPUT -s {src_ip} -j DROP",
    "MALWARE":                "pkill -f {process_name}",
    "RECON":                  "iptables -A INPUT -s {src_ip} -j DROP",
    "NETWORK_ANOMALY":        "iptables -A INPUT -s {src_ip} -j DROP",
}

# These categories always escalate to Claude regardless of confidence
ALWAYS_ESCALATE = {"ROOTKIT", "MALWARE", "PRIVILEGE_ESCALATION"}

ALLOWED_CMD_PREFIXES = (
    "iptables", "ip6tables", "ufw",
    "chmod", "chown", "chattr",
    "systemctl stop", "systemctl restart",
    "kill ", "pkill",
    "fail2ban-client",
    "auditctl",
    "aws s3api",
    "chkrootkit",
)


# ── Node 1: Triage Ingestion Agent ────────────────────────────────────────────

def triage_ingestion_node(state: SOCAgentState) -> Dict:
    """Classify the alert type and score its priority."""
    print("[SOAR Node 1] TriageIngestion — classifying alert...")

    alert    = state["raw_alert"]
    rule     = alert.get("rule", {})
    groups   = rule.get("groups", alert.get("mitre_technique", []))
    desc     = (rule.get("description") or alert.get("description", "")).lower()
    level    = int(rule.get("level", alert.get("rule_level", 0)))
    rule_id  = str(rule.get("id", alert.get("rule_id", "")))
    metadata = alert.get("metadata", {})

    # If already classified by log_orchestrator, trust the pre-computed type
    _known_types = set(REMEDIATION_MAP.keys()) | {"UNKNOWN", "CLOUD_MISCONFIGURATION"}
    pre_type = alert.get("type", "")

    if pre_type in _known_types:
        category = pre_type
    elif rule_id == "CSPM_S3_PUBLIC_04" or alert.get("event_source") == "Cloud_CSPM":
        category = "CLOUD_MISCONFIGURATION"
    elif any(g in groups for g in ["syscheck", "syscheck_file", "syscheck_entry_modified"]):
        category = "FILE_TAMPER"
    elif "brute" in desc or "authentication failure" in desc or "ssh" in desc:
        category = "BRUTE_FORCE"
    elif "rootkit" in desc or "kernel module" in desc:
        category = "ROOTKIT"
    elif "privilege" in desc or "escalation" in desc or "suid" in desc:
        category = "PRIVILEGE_ESCALATION"
    elif "malware" in desc or "virus" in desc or "trojan" in desc:
        category = "MALWARE"
    elif "web" in desc or "sql" in desc or "injection" in desc:
        category = "WEB_ATTACK"
    elif "port scan" in desc or "reconnaissance" in desc:
        category = "RECON"
    else:
        category = "UNKNOWN"

    # Priority from Wazuh level or CSPM severity
    severity = alert.get("severity", "").upper()
    if level >= 15 or severity == "CRITICAL":
        priority = "CRITICAL"
    elif level >= 12 or severity == "HIGH":
        priority = "HIGH"
    elif level >= 7 or severity == "MEDIUM":
        priority = "MEDIUM"
    else:
        priority = "LOW"

    # Extract primary source IP — handles both canonical (src_ips list) and raw formats
    _src_ips = alert.get("src_ips", [])
    src_ip = (
        alert.get("src_ip")
        or (_src_ips[0] if _src_ips else None)
        or alert.get("data", {}).get("srcip")
        or metadata.get("src_ip")
        or alert.get("metadata", {}).get("src_ip", "")
        or ""
    )

    incident_id = f"{rule_id}-{int(time.time())}"

    print(f"           Category={category}  Priority={priority}  IP={src_ip or 'none'}")

    return {
        "threat_category":  category,
        "alert_source":     alert.get("source", alert.get("event_source", "unknown")),
        "priority":         priority,
        "src_ip":           src_ip or "",
        "rule_id":          rule_id,
        "description":      rule.get("description", alert.get("description", "")),
        "incident_id":      incident_id,
    }


# ── Node 2: Threat Intel Agent ────────────────────────────────────────────────

def threat_intel_node(state: SOCAgentState) -> Dict:
    """Query AbuseIPDB and internal blacklist for the source IP."""
    print("[SOAR Node 2] ThreatIntel — querying reputation sources...")

    src_ip      = state["src_ip"]
    intel_packet: dict = {
        "abuse_score":      "0%",
        "internal_blacklist": False,
        "abuseipdb_checked": False,
        "country":          "",
        "isp":              "",
        "total_reports":    0,
    }
    is_malicious = False

    if not src_ip:
        print("           No source IP — skipping reputation check")
        return {
            "enrichment_metadata":  intel_packet,
            "ip_is_malicious":      False,
            "abuse_score":          "0%",
            "in_internal_blacklist": False,
        }

    # Check internal blacklist first (instant, no API call)
    if src_ip in INTERNAL_BLACKLIST:
        intel_packet["internal_blacklist"] = True
        intel_packet["abuse_score"]        = "100%"
        is_malicious                       = True
        print(f"           {src_ip} — INTERNAL BLACKLIST HIT")

    # Check AbuseIPDB if key available
    if ABUSEIPDB_KEY and not is_malicious:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": src_ip, "maxAgeInDays": 90},
                timeout=8,
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                intel_packet.update({
                    "abuse_score":       f"{score}%",
                    "total_reports":     d.get("totalReports", 0),
                    "country":           d.get("countryCode", ""),
                    "isp":               d.get("isp", ""),
                    "abuseipdb_checked": True,
                })
                if score >= 50:
                    is_malicious = True
                print(f"           {src_ip} AbuseIPDB score={score}%  ISP={d.get('isp','')}")
        except Exception as e:
            print(f"           AbuseIPDB error: {e}")
    elif not ABUSEIPDB_KEY:
        print("           ABUSEIPDB_KEY not set — skipping API check")

    return {
        "enrichment_metadata":   intel_packet,
        "ip_is_malicious":       is_malicious,
        "abuse_score":           intel_packet["abuse_score"],
        "in_internal_blacklist": intel_packet["internal_blacklist"],
    }


# ── Node 3: Remediation Architect Agent ───────────────────────────────────────

def remediation_architect_node(state: SOCAgentState) -> Dict:
    """
    Generate a remediation command from the deterministic allowlist.
    Flags complex cases for Claude escalation.
    """
    print("[SOAR Node 3] RemediationArchitect — selecting remediation strategy...")

    category    = state["threat_category"]
    src_ip      = state["src_ip"]
    alert       = state["raw_alert"]
    priority    = state["priority"]
    is_malicious = state["ip_is_malicious"]

    # Extract contextual values for template substitution
    path         = (alert.get("syscheck", {}).get("path")
                    or alert.get("path", "")
                    or alert.get("metadata", {}).get("path", ""))
    resource_id  = (alert.get("metadata", {}).get("resource_id", "")
                    or alert.get("resource_id", ""))
    process_name = alert.get("data", {}).get("process_name", "suspicious_process")

    # Determine if Claude deep analysis is needed
    requires_claude = (
        category in ALWAYS_ESCALATE
        or category == "UNKNOWN"
        or (priority == "CRITICAL" and not REMEDIATION_MAP.get(category))
        or (is_malicious and priority == "CRITICAL")
    )

    # Build command from template
    template = REMEDIATION_MAP.get(category, "")
    if template:
        command = template.format(
            src_ip=src_ip or "UNKNOWN_IP",
            path=path or "/etc/sensitive_file",
            resource_id=resource_id or "unknown-bucket",
            process_name=process_name,
        )
        rationale   = f"Deterministic response for {category}: command directly contains the threat"
        confidence  = "HIGH" if src_ip or path or resource_id else "MEDIUM"
    else:
        command     = f"echo 'No deterministic command for category: {category}'"
        rationale   = "No allowlist match — Claude escalation required"
        confidence  = "LOW"
        requires_claude = True

    print(f"           Command: {command[:80]}")
    print(f"           Confidence={confidence}  Escalate={requires_claude}")

    return {
        "remediation_command":  command,
        "remediation_rationale": rationale,
        "requires_claude":      requires_claude,
        "confidence":           confidence,
    }


# ── Graph assembly ─────────────────────────────────────────────────────────────

def build_soar_graph() -> StateGraph:
    builder = StateGraph(SOCAgentState)

    builder.add_node("TriageIngestion",      triage_ingestion_node)
    builder.add_node("ThreatIntel",          threat_intel_node)
    builder.add_node("RemediationArchitect", remediation_architect_node)

    builder.set_entry_point("TriageIngestion")
    builder.add_edge("TriageIngestion",      "ThreatIntel")
    builder.add_edge("ThreatIntel",          "RemediationArchitect")
    builder.add_edge("RemediationArchitect", END)

    return builder.compile()


# ── Runtime helpers ────────────────────────────────────────────────────────────

def _blank_state(alert: dict) -> SOCAgentState:
    return SOCAgentState(
        raw_alert=alert,
        threat_category="", alert_source="", priority="", src_ip="",
        rule_id="", description="",
        enrichment_metadata={}, ip_is_malicious=False,
        abuse_score="0%", in_internal_blacklist=False,
        remediation_command="", remediation_rationale="",
        requires_claude=False, confidence="",
        execution_result={}, execution_verified=False,
        claude_report={},
        incident_id="", audit_logged=False,
        errors=[],
    )


def _execute(cmd: str) -> dict:
    if DRY_RUN:
        print(f"[SOAR] DRY RUN — would execute: {cmd}")
        return {"executed": False, "dry_run": True, "command": cmd}

    if not any(cmd.strip().startswith(p) for p in ALLOWED_CMD_PREFIXES):
        print(f"[SOAR] BLOCKED — not in allowlist: {cmd}")
        return {"executed": False, "blocked": True, "command": cmd}

    if platform.system() == "Windows":
        print(f"[SOAR] SKIP — live execution disabled on Windows: {cmd}")
        return {"executed": False, "platform": "windows", "command": cmd}

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        out = (result.stdout + result.stderr).strip()
        ok  = result.returncode == 0
        print(f"[SOAR] {'SUCCESS' if ok else 'FAILED'} — {cmd}")
        return {"executed": True, "command": cmd, "returncode": result.returncode,
                "output": out, "success": ok}
    except Exception as e:
        return {"executed": False, "error": str(e), "command": cmd}


def _claude_escalate(state: SOCAgentState) -> dict:
    """Call Claude for deep analysis when the deterministic path can't handle the case."""
    if not ANTHROPIC_KEY:
        return {"error": "ANTHROPIC_API_KEY not set"}
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        prompt = f"""You are a senior SOC analyst. Analyse this alert and return a JSON SOC report:

Alert: {json.dumps(state['raw_alert'], indent=2)}
Category: {state['threat_category']}
Priority: {state['priority']}
IP Reputation: {state['abuse_score']} abuse confidence
Deterministic command attempted: {state['remediation_command']}

Return JSON only:
{{
  "incident_id": "{state['incident_id']}",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_vector": "...",
  "mitre_technique": "...",
  "intent_assessment": "...",
  "remediation_command": "single linux command",
  "remediation_rationale": "...",
  "follow_up_actions": [],
  "confidence": "HIGH|MEDIUM|LOW"
}}"""
        r = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = r.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {"error": str(e)}


def _write_audit(state: SOCAgentState, exec_result: dict) -> None:
    entry = {
        "logged_at":   datetime.now(timezone.utc).isoformat(),
        "incident_id": state["incident_id"],
        "category":    state["threat_category"],
        "priority":    state["priority"],
        "source":      state["alert_source"],
        "command":     state["remediation_command"],
        "confidence":  state["confidence"],
        "escalated":   state["requires_claude"],
        "claude":      state.get("claude_report", {}),
        "execution":   exec_result,
        "enrichment":  state["enrichment_metadata"],
    }
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[SOAR] Audit written -> {AUDIT_LOG.name}")


# ── Public entry point ─────────────────────────────────────────────────────────

_graph = build_soar_graph()


def run_soar_graph(alert: dict) -> SOCAgentState:
    """
    Run the full 3-node SOAR graph against a single alert dict.
    Executes remediation (respecting DRY_RUN), escalates to Claude if needed,
    writes audit entry, and returns the final state.
    """
    print(f"\n{'='*56}")
    print(f"  SOAR GRAPH — Injecting alert into state machine")
    print(f"{'='*56}")

    state: SOCAgentState = _graph.invoke(_blank_state(alert))

    # Claude escalation for complex cases
    if state["requires_claude"] and ANTHROPIC_KEY:
        print("[SOAR] Escalating to Claude AI Analyst...")
        claude_report = _claude_escalate(state)
        state = dict(state)
        state["claude_report"] = claude_report
        # Use Claude's command if better
        if claude_report.get("remediation_command") and not claude_report.get("error"):
            state["remediation_command"] = claude_report["remediation_command"]
            print(f"[SOAR] Claude override: {claude_report['remediation_command'][:80]}")

    # Execute
    exec_result = _execute(state["remediation_command"])
    state = dict(state)
    state["execution_result"]   = exec_result
    state["execution_verified"] = exec_result.get("success", False) or exec_result.get("dry_run", False)

    # Audit
    _write_audit(state, exec_result)
    state["audit_logged"] = True

    # Summary
    print(f"\n  INCIDENT  : {state['incident_id']}")
    print(f"  CATEGORY  : {state['threat_category']}")
    print(f"  PRIORITY  : {state['priority']}")
    print(f"  IP        : {state['src_ip'] or 'N/A'}  MALICIOUS={state['ip_is_malicious']}")
    print(f"  COMMAND   : {state['remediation_command'][:70]}")
    print(f"  CONFIDENCE: {state['confidence']}  ESCALATED={state['requires_claude']}")
    print(f"{'='*56}\n")

    return state


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--demo" in sys.argv:
        # Synthetic CSPM alert (from user's code)
        demo_alert = {
            "event_source":  "Cloud_CSPM",
            "severity":      "CRITICAL",
            "rule_id":       "CSPM_S3_PUBLIC_04",
            "description":   "Compliance Violation: Secure bucket is exposed to the world.",
            "metadata":      {
                "resource_id": "sfu-student-financial-backups",
                "src_ip":      "193.163.125.128",
            },
        }
        result = run_soar_graph(demo_alert)
        print(json.dumps({k: v for k, v in result.items() if k != "raw_alert"}, indent=2, default=str))

    elif "--local" in sys.argv:
        threat_path = _ROOT / "intelligence" / "live_threats.json"
        if not threat_path.exists():
            print(f"Not found: {threat_path}")
            sys.exit(1)
        with open(threat_path, encoding="utf-8") as f:
            stored = json.load(f)
        # If the file is a minimal record (type+status+raw_log), expand it
        # by parsing raw_log back into the canonical threat record format
        if set(stored.keys()) <= {"type", "status", "raw_log"}:
            raw = json.loads(stored.get("raw_log", "{}"))
            syscheck = raw.get("syscheck", {})
            rule     = raw.get("rule", {})
            alert = {
                "type":        stored.get("type", "UNKNOWN"),
                "source":      "wazuh-edr",
                "status":      stored.get("status", "investigating"),
                "timestamp":   raw.get("timestamp", ""),
                "rule_id":     rule.get("id", ""),
                "rule_level":  rule.get("level", 0),
                "description": rule.get("description", ""),
                "path":        syscheck.get("path", ""),
                "src_ips":     [],
                "hashes":      [syscheck.get("md5_after", "")],
                "rule":        rule,
                "syscheck":    syscheck,
                "agent":       raw.get("agent", {}),
            }
        else:
            alert = stored
        result = run_soar_graph(alert)
        print(json.dumps({k: v for k, v in result.items() if k != "raw_alert"}, indent=2, default=str))

    else:
        print("Usage:")
        print("  python response/soar_graph.py --local    # run against live_threats.json")
        print("  python response/soar_graph.py --demo     # inject synthetic CSPM alert")
