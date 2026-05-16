import os
import anthropic


def get_client() -> anthropic.Anthropic:
    """Returns a shared Anthropic client using env var."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set in environment")
    return anthropic.Anthropic(api_key=api_key)


def parse_json_response(text: str) -> dict:
    """Strips markdown fences and parses JSON from Claude responses."""
    import json
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text.strip())
