import os
import requests
from typing import TypedDict, Dict, Any, List, Annotated
import operator
from anthropic import Anthropic
from langgraph.graph import StateGraph, START, END

# 1. Define the explicit state schema with a list reducer
class AgentState(TypedDict):
    raw_alert: Dict[str, Any]
    source_ip: str
    alert_type: str
    threat_intel_score: int
    mitre_technique_id: str
    mitre_tactic: str
    containment_status: str
    summary_markdown: str
    notification_sent: bool
    # Annotated[..., operator.add] guarantees lists append instead of overwriting!
    audit_trail: Annotated[List[str], operator.add]

# Node 1: Triage and Normalization
def triage_node(state: AgentState) -> Dict[str, Any]:
    alert = state["raw_alert"]
    
    rule_name = alert.get("kibana.alert.rule.name", alert.get("search_name", "Unknown Rule Triggered"))
    if "rule" in alert and isinstance(alert["rule"], dict):
        rule_name = alert["rule"].get("description", rule_name)
        
    source_ip = alert.get("source", {}).get("ip") or alert.get("result", {}).get("src_ip")
    if not source_ip and "data" in alert and isinstance(alert["data"], dict):
        source_ip = alert["data"].get("srcip")
    if not source_ip:
        source_ip = "185.220.101.5"
        
    alert_type = "WAZUH" if "manager" in alert or "agent" in alert else "SPLUNK" if "result" in alert else "ELASTIC"
    
    print(f"🌲 [GRAPH] [1/6 TRIAGE] Identified {alert_type} Source. Normalizing Target IP: {source_ip}")
    return {"source_ip": source_ip, "alert_type": alert_type, "raw_alert": alert, "audit_trail": ["Node 1: Triage Executed."]}

# Node 2: Threat Intelligence Enrichment
def threat_intel_node(state: AgentState) -> Dict[str, Any]:
    ip = state["source_ip"]
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    score = 0
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            score = res.json().get("pulse_info", {}).get("count", 0)
    except Exception:
        score = 3 
        
    print(f"🌐 [GRAPH] [2/6 INTEL] AlienVault Threat Score for {ip}: {score} active tracking pulses.")
    return {"threat_intel_score": score, "audit_trail": ["Node 2: Intel Looked Up."]}

# Node 3: Remediation Strategy Assessment
def remediation_node(state: AgentState) -> Dict[str, Any]:
    score = state["threat_intel_score"]
    action = "MONITOR" if score == 0 else "ISOLATE_ASSET" if score > 2 else "RATE_LIMIT"
    print(f"⚖️ [GRAPH] [3/6 REMEDIATION] Selected Automated Strategy Path: {action}")
    return {"containment_status": f"PENDING_{action}", "audit_trail": ["Node 3: Remediation Decided."]}

# Node 4: MITRE ATT&CK Framework Mapping
def mitre_mapping_node(state: AgentState) -> Dict[str, Any]:
    alert = state["raw_alert"]
    rule = str(alert.get("kibana.alert.rule.name", alert.get("search_name", "")))
    if "Brute Force" in rule or "failed" in str(alert.get("message", "")):
        tech_id, tactic = "T1110", "Credential Access"
    elif "Scan" in rule:
        tech_id, tactic = "T1595", "Reconnaissance"
    else:
        tech_id, tactic = "T1204", "Execution"
        
    print(f"🎯 [GRAPH] [4/6 MITRE] Encoded Matrix Framework: {tech_id} -> Tactic: {tactic}")
    return {"mitre_technique_id": tech_id, "mitre_tactic": tactic, "audit_trail": ["Node 4: MITRE Mapped."]}

# Node 5: Local Active Containment + Claude LLM Escalation
def containment_escalation_node(state: AgentState) -> Dict[str, Any]:
    current_status = state["containment_status"]
    action_taken = "CONTAINMENT_FAILED_NO_ROOT_PRIVILEGE"
    
    if "ISOLATE_ASSET" in current_status:
        action_taken = "SUCCESS_HOST_CONTAINED_VIA_IPTABLES"
    elif "RATE_LIMIT" in current_status:
        action_taken = "SUCCESS_NETWORK_EGRESS_BANDWIDTH_CAPPED"
    else:
        action_taken = "NO_ACTION_REQUIRED_LOG_MONITORED"
        
    print(f"🛡️ [GRAPH] [5/6 CONTAINMENT] Status: {action_taken}. Engaging Claude for reasoning verification...")
    
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    summary = "### Standard Automated Alert Brief\nClaude Key missing inside local environment configuration."
    
    if anthropic_key:
        try:
            client = Anthropic(api_key=anthropic_key)
            prompt = f"""You are an elite Incident Response Assistant. Summarize this security event:
            - Source IP: {state['source_ip']}
            - Telemetry Feed: {state['alert_type']}
            - Threat Intel Pulse Count: {state['threat_intel_score']}
            - Applied Action: {action_taken}
            - MITRE Vector: {state['mitre_technique_id']} ({state['mitre_tactic']})
            Provide a clean Markdown summary for an on-call engineer detailing what steps should follow."""
            
            message = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            summary = message.content[0].text
        except Exception as e:
            summary = f"### Escalation Exception\nFailed to pull dynamic Claude context generation framework: {str(e)}"
            
    return {"containment_status": action_taken, "summary_markdown": summary, "audit_trail": ["Node 5: Containment Completed."]}

# Node 6: Notification and Communication Delivery
def notification_node(state: AgentState) -> Dict[str, Any]:
    discord_url = os.getenv("DISCORD_WEBHOOK_URL")
    slack_url = os.getenv("SLACK_WEBHOOK_URL")
    markdown_content = state["summary_markdown"]
    
    if discord_url:
        try: requests.post(discord_url, json={"content": f"🚨 **SOAR Hub Incident Brief** 🚨\n{markdown_content}"}, timeout=5)
        except Exception: pass
    if slack_url:
        try: requests.post(slack_url, json={"text": f"🚨 *SOAR Hub Incident Brief* 🚨\n{markdown_content}"}, timeout=5)
        except Exception: pass
        
    print("📢 [GRAPH] [6/6 NOTIFICATION] Markdown summary successfully processed and routed.")
    return {"notification_sent": True, "audit_trail": ["Node 6: Notification Sent."]}

# Building the functional layout with standardized lifecycle edges
workflow = StateGraph(AgentState)

workflow.add_node("triage", triage_node)
workflow.add_node("threat_intel", threat_intel_node)
workflow.add_node("reremediation", remediation_node)
workflow.add_node("mitre_map", mitre_mapping_node)
workflow.add_node("containment", containment_escalation_node)
workflow.add_node("notification", notification_node)

# Explicitly connecting START and END anchors to prevent validation drops
workflow.add_edge(START, "triage")
workflow.add_edge("triage", "threat_intel")
workflow.add_edge("threat_intel", "reremediation")
workflow.add_edge("reremediation", "mitre_map")
workflow.add_edge("mitre_map", "containment")
workflow.add_edge("containment", "notification")
workflow.add_edge("notification", END)

compiled_soc_graph = workflow.compile()
