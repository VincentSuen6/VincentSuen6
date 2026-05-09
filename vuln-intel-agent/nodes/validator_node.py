import json
import os
import anthropic
from state import AgentState


def validator_node(state: AgentState) -> AgentState:
    """Cross-references all intel sources and validates TTPs."""
    try:
        print("[Validator] Cross-referencing intel sources...")

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        prompt = f"""You are a senior threat intelligence analyst performing cross-source validation.

CVE: {state['cve_id']}
Description: {state['cve_description']}
OSINT Summary: {state['osint_summary']}
Threat Actors Identified: {state['threat_actor_mentions']}
TAXII TTPs Found: {state['taxii_ttps'][:10]}
PoC Available: {state['poc_available']}

Cross-reference all sources and determine:
1. Which MITRE ATT&CK techniques does this CVE most likely enable or represent?
2. How confident are you in this mapping? (0.0 to 1.0)
3. Any contradictions between sources?

Return JSON only — no markdown fences:
{{
  "validated_techniques": ["T1190", "T1133"],
  "confidence_score": 0.87,
  "primary_tactic": "Initial Access",
  "validation_notes": "explanation here",
  "contradictions": []
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

        state["cross_referenced_ttps"] = result.get("validated_techniques", [])
        state["confidence_score"] = result.get("confidence_score", 0.0)
        state["validation_notes"] = result.get("validation_notes", "")
        state["processing_status"] = "validation_complete"
        print(f"[Validator] Done. Confidence: {state['confidence_score']:.0%}")

    except Exception as e:
        state["errors"].append(f"Validator error: {str(e)}")
        print(f"[Validator] ERROR: {e}")

    return state
