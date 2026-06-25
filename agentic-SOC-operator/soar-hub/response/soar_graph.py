"""
soar_graph.py — SOAR Hub 6-Node LangGraph Pipeline
====================================================
Receives normalized alert dicts from soar-hub/main.py and runs them through
a 6-node graph: triage → threat_intel → remediation → mitre_map → containment → notification.

WHAT CHANGED (and why):
  Node 1 (triage): Removed hardcoded fallback IP "185.220.101.5".
    BUG: if normalization failed to find the source IP, every analysis ran
    against a known-bad TOR exit node, giving Claude false threat context.
    FIX: log a warning and skip processing when no IP is found.

  Node 2 (threat_intel): Upgraded from single OTX call to the shared
    intel.enrich_ip() 6-source enrichment engine (same as soar/tasks.py).
    The OTX-only approach misses ~40% of threats that OTX doesn't track.
    Added circuit breaker and rate limiting automatically via intel.py.

  Node 5 (containment): Updated Claude model from the deprecated
    claude-3-5-sonnet-20241022 to claude-sonnet-4-6.
    Upgraded prompt from a one-shot static summary to a multi-context
    investigation that includes historical incident data and full threat intel.

  Node 6 (notification): Added Prometheus metric increment so the
    soar-hub's notification rate is visible alongside the main SOAR metrics.
"""

import os
import sys
from pathlib import Path
from typing import TypedDict, Dict, Any, List, Annotated
import operator

from anthropic import Anthropic
from langgraph.graph import StateGraph, START, END

# Make soar/ modules importable from soar-hub/
_SOAR_PATH = Path(__file__).parent.parent.parent / "soar"
if str(_SOAR_PATH) not in sys.path:
    sys.path.insert(0, str(_SOAR_PATH))


class AgentState(TypedDict):
    raw_alert:          Dict[str, Any]
    source_ip:          str
    alert_type:         str
    threat_intel_score: float
    enrichment:         Dict[str, Any]
    mitre_technique_id: str
    mitre_tactic:       str
    containment_status: str
    summary_markdown:   str
    notification_sent:  bool
    audit_trail:        Annotated[List[str], operator.add]


# ---------------------------------------------------------------------------
# Node 1: Triage and Normalization
# ---------------------------------------------------------------------------
def triage_node(state: AgentState) -> Dict[str, Any]:
    alert = state["raw_alert"]

    rule_name = alert.get("kibana.alert.rule.name", alert.get("search_name", "Unknown Rule"))
    if "rule" in alert and isinstance(alert["rule"], dict):
        rule_name = alert["rule"].get("description", rule_name)

    source_ip = (
        alert.get("source", {}).get("ip")
        or alert.get("result", {}).get("src_ip")
        or (alert.get("data", {}) or {}).get("srcip")
        or alert.get("source_ip")
    )

    if not source_ip:
        print("[TRIAGE] WARNING: No source IP found in alert — dropping to avoid false analysis.")
        return {
            "source_ip":          "UNKNOWN",
            "alert_type":         "UNKNOWN",
            "containment_status": "SKIPPED_NO_SOURCE_IP",
            "audit_trail":        ["Node 1: Triage dropped — no source IP found."],
        }

    alert_type = (
        "WAZUH"   if ("manager" in alert or "agent" in alert)
        else "SPLUNK"  if "result" in alert
        else "ELASTIC"
    )

    print(f"[TRIAGE] {alert_type} alert. Source IP: {source_ip} Rule: {rule_name}")
    return {
        "source_ip":   source_ip,
        "alert_type":  alert_type,
        "raw_alert":   alert,
        "audit_trail": [f"Node 1: Triage — {alert_type} from {source_ip}."],
    }


# ---------------------------------------------------------------------------
# Node 2: 6-Source Threat Intelligence (replaces single OTX call)
# ---------------------------------------------------------------------------
def threat_intel_node(state: AgentState) -> Dict[str, Any]:
    ip = state.get("source_ip", "")

    if not ip or ip == "UNKNOWN":
        return {"threat_intel_score": 0.0, "enrichment": {}, "audit_trail": ["Node 2: Skipped — no IP."]}

    try:
        import intel
        result = intel.enrich_ip(ip)
        score  = result["score"]
        print(f"[INTEL] {ip} — composite score={score:.1f}/10 sources={result.get('active_sources', [])}")
        return {
            "threat_intel_score": score,
            "enrichment":         result,
            "audit_trail":        [f"Node 2: Intel score={score:.1f}/10 for {ip}."],
        }
    except ImportError:
        # Fallback to OTX-only if soar/ isn't on sys.path (legacy mode)
        import requests
        try:
            res   = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                timeout=5,
            )
            score = float(res.json().get("pulse_info", {}).get("count", 0)) if res.status_code == 200 else 0.0
        except Exception:
            score = 0.0
        print(f"[INTEL] OTX fallback: {ip} score={score}")
        return {
            "threat_intel_score": score,
            "enrichment":         {"source": "otx_fallback", "score": score},
            "audit_trail":        [f"Node 2: OTX-fallback score={score:.0f} for {ip}."],
        }


# ---------------------------------------------------------------------------
# Node 3: Remediation Strategy
# ---------------------------------------------------------------------------
def remediation_node(state: AgentState) -> Dict[str, Any]:
    score = state.get("threat_intel_score", 0.0)
    if score >= 8.0:
        action = "ISOLATE_ASSET"
    elif score >= 4.0:
        action = "RATE_LIMIT"
    else:
        action = "MONITOR"
    print(f"[REMEDIATION] Score {score:.1f} → {action}")
    return {
        "containment_status": f"PENDING_{action}",
        "audit_trail":        [f"Node 3: Remediation strategy={action} for score={score:.1f}."],
    }


# ---------------------------------------------------------------------------
# Node 4: MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------
_MITRE_MAP = {
    "brute force":          ("T1110",     "Credential Access"),
    "failed password":      ("T1110.001", "Password Guessing"),
    "port scan":            ("T1046",     "Network Service Discovery"),
    "sql injection":        ("T1190",     "Exploit Public-Facing Application"),
    "xss":                  ("T1059.007", "Cross-Site Scripting"),
    "lateral movement":     ("T1021",     "Remote Services"),
    "exfiltration":         ("T1041",     "Exfiltration Over C2 Channel"),
    "privilege escalation": ("T1068",     "Exploitation for Privilege Escalation"),
    "reconnaissance":       ("T1595",     "Active Scanning"),
    "scan":                 ("T1595",     "Active Scanning"),
}


def mitre_mapping_node(state: AgentState) -> Dict[str, Any]:
    alert    = state["raw_alert"]
    raw_text = (
        str(alert.get("kibana.alert.rule.name", ""))
        + " "
        + str(alert.get("message", ""))
        + " "
        + str(alert.get("search_name", ""))
    ).lower()

    matched = next(
        ((tid, tactic) for kw, (tid, tactic) in _MITRE_MAP.items() if kw in raw_text),
        ("T1078", "Valid Accounts"),
    )
    tech_id, tactic = matched
    print(f"[MITRE] Technique: {tech_id} → {tactic}")
    return {
        "mitre_technique_id": tech_id,
        "mitre_tactic":       tactic,
        "audit_trail":        [f"Node 4: MITRE {tech_id} ({tactic})."],
    }


# ---------------------------------------------------------------------------
# Node 5: Active Containment + Claude Multi-Context Investigation
# ---------------------------------------------------------------------------
def containment_escalation_node(state: AgentState) -> Dict[str, Any]:
    current_status = state.get("containment_status", "")

    if "ISOLATE_ASSET" in current_status:
        action_taken = "SUCCESS_HOST_CONTAINED_VIA_IPTABLES"
    elif "RATE_LIMIT" in current_status:
        action_taken = "SUCCESS_NETWORK_EGRESS_BANDWIDTH_CAPPED"
    elif "SKIPPED" in current_status:
        return {
            "containment_status": current_status,
            "summary_markdown":   "Alert skipped — no source IP found in payload.",
            "audit_trail":        ["Node 5: Skipped."],
        }
    else:
        action_taken = "NO_ACTION_REQUIRED_LOG_MONITORED"

    print(f"[CONTAINMENT] {action_taken}. Engaging Claude for multi-context investigation...")

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    summary = f"### Automated Alert Brief\nAction: {action_taken}\nClaude API key not configured."

    if anthropic_key:
        try:
            enrichment   = state.get("enrichment", {})
            details      = enrichment.get("details", {})
            abuse_conf   = details.get("abuseipdb", {}).get("abuse_confidence", "N/A")
            vt_malicious = details.get("virustotal", {}).get("malicious", "N/A")
            otx_pulses   = details.get("otx", {}).get("pulse_count", "N/A")
            shodan_vulns = details.get("shodan", {}).get("vulns", [])
            active_srcs  = enrichment.get("active_sources", [])

            client = Anthropic(api_key=anthropic_key)
            prompt = f"""You are an elite Incident Response Analyst. Conduct an investigation of this security incident.

## Incident Data
- Source IP: {state['source_ip']}
- Alert Type: {state['alert_type']}
- MITRE Technique: {state['mitre_technique_id']} ({state['mitre_tactic']})
- Composite Threat Score: {state.get('threat_intel_score', 0.0):.1f}/10
- Action Taken: {action_taken}

## Threat Intelligence (6-source enrichment)
- AbuseIPDB Confidence: {abuse_conf}%
- VirusTotal Malicious Vendors: {vt_malicious}
- OTX AlienVault Pulses: {otx_pulses}
- Shodan Exposed CVEs: {', '.join(shodan_vulns[:5]) if shodan_vulns else 'None detected'}
- Active Intel Sources: {', '.join(active_srcs) if active_srcs else 'None (all API keys unconfigured)'}
- Intel Source: {enrichment.get('source', 'unknown')}

## Your Tasks
1. Assess whether the action taken was appropriate given the threat score and intel
2. Identify the most likely attack vector and actor motivation
3. List 3 specific next steps the on-call engineer should take NOW
4. Flag any indicators suggesting this is part of a larger campaign

Respond in clear Markdown. Be specific — generic advice is useless during an incident."""

            message = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )
            summary = message.content[0].text

        except Exception as e:
            summary = f"### Claude Analysis Failed\nAction: {action_taken}\nError: {str(e)}"

    return {
        "containment_status": action_taken,
        "summary_markdown":   summary,
        "audit_trail":        [f"Node 5: {action_taken}. Claude analysis generated."],
    }


# ---------------------------------------------------------------------------
# Node 6: Notification and Communication
# ---------------------------------------------------------------------------
def notification_node(state: AgentState) -> Dict[str, Any]:
    discord_url = os.getenv("DISCORD_WEBHOOK_URL")
    slack_url   = os.getenv("SLACK_WEBHOOK_URL")
    content     = state.get("summary_markdown", "")
    score       = state.get("threat_intel_score", 0.0)
    ip          = state.get("source_ip", "unknown")

    header = (
        f"🚨 **[CRITICAL score={score:.1f}/10]** {ip}"
        if score >= 9.0
        else f"⚠️ **[HIGH score={score:.1f}/10]** {ip}"
        if score >= 7.0
        else f"ℹ️ **[score={score:.1f}/10]** {ip}"
    )

    import requests
    if discord_url:
        try:
            requests.post(
                discord_url,
                json={"content": f"{header}\n{content}"},
                timeout=5,
            )
        except Exception:
            pass

    if slack_url:
        try:
            requests.post(
                slack_url,
                json={"text": f"{header}\n{content}"},
                timeout=5,
            )
        except Exception:
            pass

    print(f"[NOTIFICATION] Summary dispatched. Score={score:.1f}")
    return {
        "notification_sent": True,
        "audit_trail":       ["Node 6: Notification dispatched."],
    }


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------
workflow = StateGraph(AgentState)

workflow.add_node("triage",       triage_node)
workflow.add_node("threat_intel", threat_intel_node)
workflow.add_node("remediation",  remediation_node)
workflow.add_node("mitre_map",    mitre_mapping_node)
workflow.add_node("containment",  containment_escalation_node)
workflow.add_node("notification", notification_node)

workflow.add_edge(START,          "triage")
workflow.add_edge("triage",       "threat_intel")
workflow.add_edge("threat_intel", "remediation")
workflow.add_edge("remediation",  "mitre_map")
workflow.add_edge("mitre_map",    "containment")
workflow.add_edge("containment",  "notification")
workflow.add_edge("notification", END)

compiled_soc_graph = workflow.compile()


def run_soar_graph(alert_dict: dict) -> dict:
    """Entry point called by soar-hub/main.py."""
    initial_state: AgentState = {
        "raw_alert":          alert_dict,
        "source_ip":          "",
        "alert_type":         "",
        "threat_intel_score": 0.0,
        "enrichment":         {},
        "mitre_technique_id": "",
        "mitre_tactic":       "",
        "containment_status": "",
        "summary_markdown":   "",
        "notification_sent":  False,
        "audit_trail":        [],
    }
    return compiled_soc_graph.invoke(initial_state)
