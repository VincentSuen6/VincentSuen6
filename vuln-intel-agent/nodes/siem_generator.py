import json
import os
import anthropic
from state import AgentState


def siem_generator_node(state: AgentState) -> AgentState:
    """Generates actionable Wazuh and Splunk detection rules."""
    try:
        print("[SIEM Generator] Generating detection rules...")

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        primary_technique = (
            state["mitre_techniques"][0] if state["mitre_techniques"] else {}
        )

        prompt = f"""You are a detection engineer specializing in SIEM rule authoring.

CVE: {state['cve_id']}
Primary MITRE Technique: {primary_technique}
Attack Chain: {state['attack_chain']}
Affected Products: {state['affected_products'][:3]}
Severity: {state['cve_severity']}
CVSS: {state['cve_cvss_score']}
OSINT Summary: {state['osint_summary']}

Generate two production-ready detection rules:

1. A Wazuh XML rule (use rule id 100100, follow Wazuh rule XML syntax exactly)
2. A Splunk SPL search query (realistic field names, pipe chains)

Return JSON only — no markdown fences:
{{
  "wazuh_rule": "<rule id=\\"100100\\" level=\\"12\\">\\n  <decoded_as>json</decoded_as>\\n  ...\\n</rule>",
  "splunk_query": "index=* sourcetype=... | ...",
  "alert_severity": "critical",
  "detection_notes": "What this detects and why it is effective"
}}"""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)

        state["wazuh_rule"] = result.get("wazuh_rule", "")
        state["splunk_query"] = result.get("splunk_query", "")
        state["alert_severity"] = result.get("alert_severity", "medium")
        state["processing_status"] = "complete"
        print(f"[SIEM Generator] Done. Alert severity: {state['alert_severity'].upper()}")

    except Exception as e:
        state["errors"].append(f"SIEM Generator error: {str(e)}")
        print(f"[SIEM Generator] ERROR: {e}")

    return state
