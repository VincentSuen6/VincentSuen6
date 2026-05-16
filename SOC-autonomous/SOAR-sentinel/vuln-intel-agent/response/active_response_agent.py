"""
active_response_agent.py — Response Layer
==========================================
Polls GitHub for changes to intelligence/live_threats.json.
When a new commit is detected it:
  1. Reads the threat JSON
  2. Sends it to Claude with the SOC analyst system prompt
  3. Parses Claude's remediation command
  4. Executes the command locally (with safety validation)
  5. Appends a full SOC report entry to response/audit_trail.jsonl

On your Ubuntu VM:
    python3 response/active_response_agent.py

Environment variables (add to .env):
    GITHUB_TOKEN        — GitHub personal access token (read scope)
    GITHUB_REPO         — e.g. VincentSuen6/vuln-intel-agent
    ANTHROPIC_API_KEY   — your Anthropic key
    DRY_RUN             — set to "false" to actually execute commands (default: true)
    POLL_INTERVAL       — seconds between GitHub checks (default: 60)
"""

import json
import os
import sys
import time
import subprocess
import platform
import requests
import anthropic
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN    = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO     = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH   = os.getenv("GITHUB_BRANCH", "main")
GITHUB_PATH     = "intelligence/live_threats.json"
POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL", "60"))
DRY_RUN         = os.getenv("DRY_RUN", "true").lower() != "false"
ANTHROPIC_KEY   = os.getenv("ANTHROPIC_API_KEY", "")

GITHUB_API      = "https://api.github.com"
GITHUB_HEADERS  = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

AUDIT_LOG       = Path(__file__).parent / "audit_trail.jsonl"

# Safety: only these command prefixes are ever permitted to execute.
ALLOWED_CMD_PREFIXES = (
    "iptables", "ip6tables", "ufw",             # firewall
    "chmod", "chown", "chattr",                 # permissions
    "systemctl stop", "systemctl restart",      # service control
    "kill ", "pkill",                            # process control
    "fail2ban-client",                           # ban IPs
    "auditctl",                                  # audit rules
)

# ── SOC System Prompt ─────────────────────────────────────────────────────────
SOC_SYSTEM_PROMPT = """You are the Autonomous Accountability Intelligence Agent — a senior SOC analyst AI embedded in an automated detection-response pipeline.

When given a Wazuh security alert from live_threats.json, you must:

1. **Identify the Attack Vector** — name the specific technique (e.g. FILE_TAMPER on a sensitive path, SSH BRUTE_FORCE, PRIVILEGE_ESCALATION). Cite the MITRE ATT&CK technique ID if present.

2. **Assess Intent** — explain WHY an attacker would target this specific path, service, or resource. What does compromising it give them?

3. **Recommend Remediation** — provide ONE specific Linux shell command (iptables, chmod, chown, chattr, fail2ban-client, systemctl, etc.) that immediately neutralises or contains the threat. The command must be executable as-is.

4. **SOC Report Entry** — format your full response as a structured JSON object:

{
  "incident_id": "<rule_id>-<epoch_seconds>",
  "timestamp": "<ISO8601>",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_vector": "<type and description>",
  "mitre_technique": "<T-code and name>",
  "intent_assessment": "<why this target, what attacker gains>",
  "remediation_command": "<single executable Linux command>",
  "remediation_rationale": "<why this command stops the threat>",
  "follow_up_actions": ["<action1>", "<action2>"],
  "confidence": "HIGH|MEDIUM|LOW"
}

Return ONLY the JSON object. No markdown fences, no explanation outside the JSON."""


# ── GitHub helpers ─────────────────────────────────────────────────────────────

def get_latest_commit_sha() -> str | None:
    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/commits"
    r = requests.get(
        url,
        headers=GITHUB_HEADERS,
        params={"path": GITHUB_PATH, "sha": GITHUB_BRANCH, "per_page": 1},
    )
    if r.status_code == 200 and r.json():
        return r.json()[0]["sha"]
    return None


def fetch_live_threats() -> dict | None:
    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}"
    r = requests.get(url, headers=GITHUB_HEADERS, params={"ref": GITHUB_BRANCH})
    if r.status_code == 200:
        import base64
        content = base64.b64decode(r.json()["content"]).decode()
        return json.loads(content)
    return None


# ── Claude analysis ────────────────────────────────────────────────────────────

def analyse_threat(threat: dict) -> dict:
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    user_msg = f"""New security alert from live_threats.json:

{json.dumps(threat, indent=2)}

Produce your SOC report entry now."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SOC_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    text = response.content[0].text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text.strip())


# ── Command safety gate ────────────────────────────────────────────────────────

def is_command_safe(cmd: str) -> bool:
    """Returns True only if the command starts with an approved prefix."""
    cmd = cmd.strip()
    return any(cmd.startswith(p) for p in ALLOWED_CMD_PREFIXES)


def execute_remediation(cmd: str) -> dict:
    """Execute the remediation command and return a result record."""
    if DRY_RUN:
        print(f"[Response] DRY RUN — would execute: {cmd}")
        return {"executed": False, "dry_run": True, "command": cmd, "output": ""}

    if not is_command_safe(cmd):
        print(f"[Response] BLOCKED — command not in allowlist: {cmd}")
        return {"executed": False, "blocked": True, "command": cmd, "reason": "not in allowlist"}

    if platform.system() == "Windows":
        print(f"[Response] SKIP — live execution disabled on Windows. Command: {cmd}")
        return {"executed": False, "platform": "windows", "command": cmd}

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        success = result.returncode == 0
        status = "SUCCESS" if success else "FAILED"
        print(f"[Response] {status} — {cmd}")
        if output:
            print(f"           {output[:200]}")
        return {
            "executed": True,
            "command": cmd,
            "returncode": result.returncode,
            "output": output,
            "success": success,
        }
    except subprocess.TimeoutExpired:
        return {"executed": False, "error": "timeout", "command": cmd}
    except Exception as e:
        return {"executed": False, "error": str(e), "command": cmd}


# ── Audit trail ────────────────────────────────────────────────────────────────

def write_audit_entry(threat: dict, report: dict, exec_result: dict) -> None:
    entry = {
        "logged_at":      datetime.now(timezone.utc).isoformat(),
        "threat_type":    threat.get("type"),
        "agent":          threat.get("agent_name"),
        "soc_report":     report,
        "execution":      exec_result,
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[Response] Audit entry written → {AUDIT_LOG}")


# ── Main polling loop ──────────────────────────────────────────────────────────

def validate_config():
    missing = []
    if not GITHUB_TOKEN:
        missing.append("GITHUB_TOKEN")
    if not GITHUB_REPO:
        missing.append("GITHUB_REPO")
    if not ANTHROPIC_KEY:
        missing.append("ANTHROPIC_API_KEY")
    if missing:
        print(f"[Response] ERROR — Missing env vars: {', '.join(missing)}")
        sys.exit(1)


def run():
    validate_config()

    mode = "DRY RUN (simulation)" if DRY_RUN else "LIVE EXECUTION"
    print(f"[Response] Active Response Agent started — {mode}")
    print(f"[Response] Polling github.com/{GITHUB_REPO} every {POLL_INTERVAL}s")
    print(f"[Response] Audit log → {AUDIT_LOG}\n")

    last_sha = None

    while True:
        try:
            current_sha = get_latest_commit_sha()

            if current_sha and current_sha != last_sha:
                if last_sha is not None:
                    print(f"\n[Response] New commit detected: {current_sha[:12]}")
                    threat = fetch_live_threats()
                    if not threat:
                        print("[Response] Could not fetch live_threats.json")
                    else:
                        print(f"[Response] Threat type: {threat.get('type')} — analysing with Claude...")
                        report      = analyse_threat(threat)
                        cmd         = report.get("remediation_command", "")
                        exec_result = execute_remediation(cmd)
                        write_audit_entry(threat, report, exec_result)

                        print(f"\n{'='*60}")
                        print(f"  INCIDENT  : {report.get('incident_id')}")
                        print(f"  SEVERITY  : {report.get('severity')}")
                        print(f"  VECTOR    : {report.get('attack_vector', '')[:80]}")
                        print(f"  MITRE     : {report.get('mitre_technique')}")
                        print(f"  INTENT    : {report.get('intent_assessment', '')[:120]}")
                        print(f"  REMEDIATE : {cmd}")
                        print(f"  CONFIDENCE: {report.get('confidence')}")
                        print(f"{'='*60}\n")
                else:
                    print(f"[Response] Baseline commit: {current_sha[:12]} — watching for changes...")

                last_sha = current_sha

        except requests.RequestException as e:
            print(f"[Response] Network error: {e}")
        except Exception as e:
            print(f"[Response] Unexpected error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    # One-shot mode: analyse the local live_threats.json right now (no GitHub polling)
    if "--local" in sys.argv:
        local_path = Path(__file__).parent.parent / "intelligence" / "live_threats.json"
        if not local_path.exists():
            print(f"[Response] File not found: {local_path}")
            sys.exit(1)
        if not ANTHROPIC_KEY:
            print("[Response] ERROR — ANTHROPIC_API_KEY not set")
            sys.exit(1)

        with open(local_path) as f:
            threat = json.load(f)

        print(f"[Response] Analysing local threat ({threat.get('type')}) with Claude...\n")
        report      = analyse_threat(threat)
        cmd         = report.get("remediation_command", "")
        exec_result = execute_remediation(cmd)
        write_audit_entry(threat, report, exec_result)

        print(json.dumps(report, indent=2))
        print(f"\nAudit entry written → {AUDIT_LOG}")
        sys.exit(0)

    run()
