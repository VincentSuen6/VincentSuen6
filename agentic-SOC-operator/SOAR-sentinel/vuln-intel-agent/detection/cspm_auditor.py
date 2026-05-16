"""
cspm_auditor.py — Cloud Security Posture Management
====================================================
Polls cloud infrastructure for security misconfigurations and feeds
alerts into the shared event_queue (same pipeline as Wazuh + Elastic).

What it checks (simulated lab mode — no real AWS credentials needed):
  • S3 buckets set to public — T1530 (Data from Cloud Storage)
  • Security groups with 0.0.0.0/0 on sensitive ports — T1190
  • Unencrypted storage volumes
  • IAM users without MFA — T1556

In production: swap simulated_checks() for real boto3 / gcloud API calls.

Feeds into:
  • Shared event_queue → enrichment → Splunk HEC → SOAR graph → GitHub

Environment variables:
  AWS_REGION           — AWS region (default: us-east-1)
  CSPM_POLL_INTERVAL   — seconds between audits (default: 120)
  CSPM_LIVE_MODE       — "true" to use real boto3 calls (requires AWS creds)

On your Ubuntu VM:
    python3 detection/cspm_auditor.py --once      # single audit pass
    python3 detection/cspm_auditor.py             # continuous polling loop
"""

import json
import os
import sys
import time
import requests
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

CSPM_POLL_INTERVAL = int(os.getenv("CSPM_POLL_INTERVAL", "120"))
CSPM_LIVE_MODE     = os.getenv("CSPM_LIVE_MODE", "false").lower() == "true"
AWS_REGION         = os.getenv("AWS_REGION", "us-east-1")

SPLUNK_HOST      = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_HEC_PORT  = int(os.getenv("SPLUNK_HEC_PORT", "8088"))
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX     = os.getenv("SPLUNK_INDEX", "security")
HEC_URL          = f"http://{SPLUNK_HOST}:{SPLUNK_HEC_PORT}/services/collector"
HEC_HEADERS      = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}


# ── Simulated infrastructure checks (lab mode) ────────────────────────────────

def simulated_checks() -> list[dict]:
    """
    Returns a list of simulated infrastructure states for lab/demo use.
    In production, replace with boto3.client('s3').list_buckets() etc.
    """
    return [
        {
            "cloud_provider":  "AWS_Simulated",
            "resource_id":     "sfu-student-financial-backups",
            "resource_type":   "S3_Bucket",
            "region":          AWS_REGION,
            "configuration":   {"IsPublic": True, "EncryptionEnabled": True},
            "timestamp":       time.time(),
            "rule_id":         "CSPM_S3_PUBLIC_04",
            "severity":        "CRITICAL",
            "description":     "S3 bucket with sensitive data is publicly accessible",
        },
        {
            "cloud_provider":  "AWS_Simulated",
            "resource_id":     "sg-0a1b2c3d4e5f",
            "resource_type":   "SecurityGroup",
            "region":          AWS_REGION,
            "configuration":   {"InboundRule": "0.0.0.0/0:22", "Port": 22},
            "timestamp":       time.time(),
            "rule_id":         "CSPM_SG_SSH_OPEN_01",
            "severity":        "HIGH",
            "description":     "Security group allows SSH (port 22) from 0.0.0.0/0",
        },
        {
            "cloud_provider":  "AWS_Simulated",
            "resource_id":     "vol-0abc123def456",
            "resource_type":   "EBS_Volume",
            "region":          AWS_REGION,
            "configuration":   {"Encrypted": False, "Attached": True},
            "timestamp":       time.time(),
            "rule_id":         "CSPM_EBS_UNENCRYPTED_02",
            "severity":        "MEDIUM",
            "description":     "EBS volume is unencrypted — data at rest exposure",
        },
        {
            "cloud_provider":  "AWS_Simulated",
            "resource_id":     "iam-user-devops-prod",
            "resource_type":   "IAM_User",
            "region":          "global",
            "configuration":   {"MFAEnabled": False, "HasConsoleAccess": True},
            "timestamp":       time.time(),
            "rule_id":         "CSPM_IAM_NO_MFA_03",
            "severity":        "HIGH",
            "description":     "IAM user with console access has no MFA configured",
        },
    ]


# ── Live checks via boto3 ──────────────────────────────────────────────────────

def live_checks() -> list[dict]:
    """Real AWS posture checks — requires boto3 and valid AWS credentials."""
    try:
        import boto3
    except ImportError:
        print("[CSPM] boto3 not installed — falling back to simulated mode")
        return simulated_checks()

    findings = []
    try:
        s3 = boto3.client("s3", region_name=AWS_REGION)
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                acl    = s3.get_bucket_acl(Bucket=name)
                public = any(
                    g.get("URI", "") == "http://acs.amazonaws.com/groups/global/AllUsers"
                    for g in (grant.get("Grantee", {}) for grant in acl.get("Grants", []))
                )
                if public:
                    findings.append({
                        "cloud_provider": "AWS",
                        "resource_id":    name,
                        "resource_type":  "S3_Bucket",
                        "region":         AWS_REGION,
                        "configuration":  {"IsPublic": True},
                        "timestamp":      time.time(),
                        "rule_id":        "CSPM_S3_PUBLIC_04",
                        "severity":       "CRITICAL",
                        "description":    f"S3 bucket {name} is publicly accessible",
                    })
            except Exception:
                continue
    except Exception as e:
        print(f"[CSPM] AWS S3 check failed: {e}")

    return findings or simulated_checks()


# ── CSPM severity → Wazuh-compatible level ─────────────────────────────────────

SEVERITY_LEVEL = {"CRITICAL": 15, "HIGH": 12, "MEDIUM": 9, "LOW": 6}

CSPM_MITRE = {
    "S3_Bucket":     {"id": ["T1530"],    "tactic": ["Collection"]},
    "SecurityGroup": {"id": ["T1190"],    "tactic": ["Initial Access"]},
    "EBS_Volume":    {"id": ["T1005"],    "tactic": ["Collection"]},
    "IAM_User":      {"id": ["T1556"],    "tactic": ["Credential Access"]},
}


def to_threat_record(finding: dict) -> dict:
    """Convert a CSPM finding into the canonical threat record schema."""
    resource_type = finding.get("resource_type", "Unknown")
    severity      = finding.get("severity", "MEDIUM")
    mitre         = CSPM_MITRE.get(resource_type, {"id": ["T1078"], "tactic": ["Initial Access"]})

    return {
        "type":            "CLOUD_MISCONFIGURATION",
        "source":          "cspm",
        "event_source":    "Cloud_CSPM",
        "status":          "investigating",
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "rule_id":         finding.get("rule_id", "CSPM_UNKNOWN"),
        "rule_level":      SEVERITY_LEVEL.get(severity, 9),
        "description":     finding.get("description", ""),
        "agent_name":      f"cspm/{finding.get('cloud_provider', 'AWS')}",
        "severity":        severity,
        "mitre_technique": mitre["id"],
        "mitre_tactic":    mitre["tactic"],
        "resource_id":     finding.get("resource_id", ""),
        "resource_type":   resource_type,
        "cloud_provider":  finding.get("cloud_provider", "AWS"),
        "region":          finding.get("region", ""),
        "configuration":   finding.get("configuration", {}),
        "src_ips":         [],
        "hashes":          [],
        "cve_id":          None,
        "enrichment":      {},
        "raw_log":         json.dumps(finding),
        # Pass through for SOAR graph TriageIngestion
        "rule":            {
            "id":          finding.get("rule_id", ""),
            "level":       SEVERITY_LEVEL.get(severity, 9),
            "description": finding.get("description", ""),
            "groups":      ["cspm", "cloud"],
            "mitre":       mitre,
        },
        "metadata": {
            "resource_id": finding.get("resource_id", ""),
        },
    }


# ── Splunk HEC sender (standalone, no dependency on splunk_hec.py) ─────────────

def ship_to_splunk(threat: dict) -> None:
    if not SPLUNK_HEC_TOKEN:
        print("[CSPM] SPLUNK_HEC_TOKEN not set — skipping HEC push")
        return
    payload = {
        "time":       time.time(),
        "host":       threat.get("agent_name", "cspm"),
        "source":     "cspm_auditor",
        "sourcetype": "cspm:finding",
        "index":      SPLUNK_INDEX,
        "event":      {k: v for k, v in threat.items() if k != "raw_log"},
    }
    try:
        r = requests.post(HEC_URL, json=payload, headers=HEC_HEADERS, timeout=10, verify=False)
        if r.status_code == 200:
            print(f"[CSPM] Shipped to Splunk: {threat['rule_id']} ({threat['severity']})")
        else:
            print(f"[CSPM] Splunk HEC error {r.status_code}: {r.text[:100]}")
    except requests.ConnectionError:
        print(f"[CSPM] Splunk unreachable at {HEC_URL}")
    except Exception as e:
        print(f"[CSPM] HEC error: {e}")


# ── Main audit loop ────────────────────────────────────────────────────────────

def evaluate_posture(event_queue=None) -> list[dict]:
    """
    Run one full posture audit pass. Feeds findings into event_queue if provided,
    otherwise ships directly to Splunk HEC and returns the list of threats.
    """
    checks  = live_checks() if CSPM_LIVE_MODE else simulated_checks()
    threats = []

    for finding in checks:
        config  = finding.get("configuration", {})
        violates = (
            config.get("IsPublic") is True
            or (config.get("InboundRule") and "0.0.0.0/0" in config.get("InboundRule", ""))
            or config.get("Encrypted") is False
            or (config.get("MFAEnabled") is False and config.get("HasConsoleAccess"))
        )

        if not violates:
            continue

        threat = to_threat_record(finding)
        print(f"[CSPM] VIOLATION: {threat['rule_id']} — {threat['description'][:70]}")

        if event_queue is not None:
            event_queue.put(threat)
        else:
            ship_to_splunk(threat)

        threats.append(threat)

    print(f"[CSPM] Audit complete — {len(threats)} violation(s) found")
    return threats


def run(event_queue=None) -> None:
    """Continuous polling loop — call with event_queue to integrate with log_orchestrator."""
    mode = "LIVE (boto3)" if CSPM_LIVE_MODE else "SIMULATED"
    print(f"[CSPM] Cloud posture auditor started — {mode} mode")
    print(f"[CSPM] Polling every {CSPM_POLL_INTERVAL}s")

    while True:
        evaluate_posture(event_queue)
        time.sleep(CSPM_POLL_INTERVAL)


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--once" in sys.argv:
        # Single pass — ship to Splunk + run through SOAR graph
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from response.soar_graph import run_soar_graph

        threats = evaluate_posture()
        for t in threats:
            print(f"\n[CSPM] Running SOAR graph for: {t['rule_id']}")
            run_soar_graph(t)
    else:
        run()
