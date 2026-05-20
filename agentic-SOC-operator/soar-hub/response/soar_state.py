from typing import TypedDict, Dict, Any, List

class AgentState(TypedDict):
    # Core Data
    raw_alert: Dict[str, Any]
    source_ip: str
    alert_type: str
    
    # Enrichment & Analysis Layers
    threat_intel_score: int
    mitre_technique_id: str
    mitre_tactic: str
    
    # Action & AI Execution States
    containment_status: str
    summary_markdown: str
    notification_sent: bool
    
    # Audit trail capturing execution sequence
    audit_trail: List[str]
