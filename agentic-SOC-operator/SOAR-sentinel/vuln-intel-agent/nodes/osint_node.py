import json
import os
import anthropic
from state import AgentState


def osint_node(state: AgentState) -> AgentState:
    """Uses Claude to gather and summarize OSINT on the CVE."""
    try:
        print(f"[OSINT Node] Gathering intel on {state['cve_id']}...")

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        prompt = f"""You are a threat intelligence analyst.

CVE ID: {state['cve_id']}
Description: {state['cve_description']}
CVSS Score: {state['cve_cvss_score']} ({state['cve_severity']})
Affected Products: {', '.join(state['affected_products'][:5])}

Based on your knowledge of this vulnerability:
1. Is a public proof-of-concept exploit likely available?
2. Which threat actor groups have been known to exploit similar vulnerabilities?
3. What is the typical attack pattern for this type of vuln?
4. What OSINT sources would have the most relevant intel?

Respond in JSON format only — no markdown fences:
{{
  "poc_available": true,
  "confidence": "high",
  "threat_actors": ["actor1", "actor2"],
  "attack_pattern": "description",
  "osint_summary": "2-3 sentence summary",
  "exploit_references": ["url1", "url2"]
}}"""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)

        state["poc_available"] = result.get("poc_available", False)
        state["threat_actor_mentions"] = result.get("threat_actors", [])
        state["osint_summary"] = result.get("osint_summary", "")
        state["exploit_references"] = result.get("exploit_references", [])
        state["processing_status"] = "osint_complete"
        print(f"[OSINT Node] Done. PoC available: {state['poc_available']}")

    except Exception as e:
        state["errors"].append(f"OSINT Node error: {str(e)}")
        print(f"[OSINT Node] ERROR: {e}")

    return state
