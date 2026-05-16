import json
import os
import anthropic
from state import AgentState


def mitre_mapper_node(state: AgentState) -> AgentState:
    """Final precise mapping to MITRE ATT&CK framework."""
    try:
        print("[MITRE Mapper] Mapping to ATT&CK framework...")

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        prompt = f"""You are a MITRE ATT&CK expert.

CVE: {state['cve_id']}
Validated Techniques: {state['cross_referenced_ttps']}
Confidence Score: {state['confidence_score']}
CVE Description: {state['cve_description']}
Affected Products: {state['affected_products'][:5]}

Produce a precise ATT&CK mapping:
1. Map to specific technique IDs with sub-techniques where applicable (e.g. T1190, T1059.003)
2. Identify the full attack chain — which tactics are used in order
3. For each technique, provide a short rationale tied to this specific CVE

Return JSON only — no markdown fences:
{{
  "techniques": [
    {{
      "id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "confidence": "high",
      "rationale": "CVE directly exploits exposed service"
    }}
  ],
  "attack_chain": ["Reconnaissance", "Initial Access", "Execution"],
  "primary_technique": "T1190"
}}"""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)

        state["mitre_techniques"] = result.get("techniques", [])
        state["attack_chain"] = result.get("attack_chain", [])
        state["mitre_tactics"] = list(
            {t["tactic"] for t in result.get("techniques", [])}
        )
        state["processing_status"] = "mitre_complete"
        print(f"[MITRE Mapper] Done. Techniques mapped: {len(state['mitre_techniques'])}")

    except Exception as e:
        state["errors"].append(f"MITRE Mapper error: {str(e)}")
        print(f"[MITRE Mapper] ERROR: {e}")

    return state
