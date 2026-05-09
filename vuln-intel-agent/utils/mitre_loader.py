"""
Ground-truth ATT&CK technique mappings for known CVEs.
Used by the accuracy test suite to validate the agent's outputs.
Each entry maps a CVE ID to its NVD-documented / CTI-documented primary technique.
"""

GROUND_TRUTH: dict[str, dict] = {
    "CVE-2024-3400":   {"technique": "T1190", "tactic": "Initial Access",    "name": "Exploit Public-Facing Application"},
    "CVE-2024-21413":  {"technique": "T1566.001", "tactic": "Initial Access", "name": "Spearphishing Attachment"},
    "CVE-2023-44487":  {"technique": "T1499.004", "tactic": "Impact",         "name": "Application or System Exploitation"},
    "CVE-2023-23397":  {"technique": "T1566.001", "tactic": "Initial Access", "name": "Spearphishing Attachment"},
    "CVE-2023-20198":  {"technique": "T1190",     "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "CVE-2022-30190":  {"technique": "T1566.001", "tactic": "Initial Access", "name": "Spearphishing Attachment"},
    "CVE-2021-44228":  {"technique": "T1190",     "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "CVE-2021-34527":  {"technique": "T1068",     "tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation"},
    "CVE-2021-26855":  {"technique": "T1190",     "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "CVE-2020-1472":   {"technique": "T1210",     "tactic": "Lateral Movement", "name": "Exploitation of Remote Services"},
    "CVE-2019-19781":  {"technique": "T1190",     "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "CVE-2018-13379":  {"technique": "T1190",     "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "CVE-2017-0144":   {"technique": "T1210",     "tactic": "Lateral Movement", "name": "Exploitation of Remote Services"},
    "CVE-2021-40444":  {"technique": "T1566.001", "tactic": "Initial Access", "name": "Spearphishing Attachment"},
    "CVE-2022-22965":  {"technique": "T1190",     "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
}


def get_ground_truth(cve_id: str) -> dict | None:
    return GROUND_TRUTH.get(cve_id)


def list_test_cves() -> list[str]:
    return list(GROUND_TRUTH.keys())
