from typing import TypedDict, List, Dict


class AgentState(TypedDict):
    # Input
    cve_id: str

    # CVE Node outputs
    cve_description: str
    cve_severity: str
    cve_cvss_score: float
    affected_products: List[str]
    cve_published_date: str

    # OSINT Node outputs
    exploit_references: List[str]
    poc_available: bool
    threat_actor_mentions: List[str]
    osint_summary: str

    # TAXII/STIX Node outputs
    stix_indicators: List[Dict]
    related_campaigns: List[str]
    taxii_ttps: List[str]

    # Validator outputs
    cross_referenced_ttps: List[str]
    confidence_score: float
    validation_notes: str

    # MITRE Mapper outputs
    mitre_techniques: List[Dict]
    mitre_tactics: List[str]
    attack_chain: List[str]

    # SIEM Generator outputs
    wazuh_rule: str
    splunk_query: str
    alert_severity: str

    # Malware Behavior Analysis outputs
    malware_families: List[str]
    behavior_timeline: List[Dict]
    ransomware_complexity_trend: str
    exploit_timing_analysis: str
    attacker_adaptation_notes: str
    behavior_mitre_mapping: List[Dict]

    # Metadata
    errors: List[str]
    processing_status: str
