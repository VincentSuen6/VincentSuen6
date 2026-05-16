========================================================================================
TIER 1: THE RESEARCH & DETECTION ENGINEERING LAB (ELASTIC SIEM)
========================================================================================

 [ Threat Emulation ] ──▶ [ Target Victim VM ] ──▶ [ Elastic Agent ] ──▶ [ Elastic Cloud SIEM ]
   (Parrot OS / Kali)       (Win 11 / Ubuntu)        (Sysmon & Zeek)      (Extract IOCs & TTPs)
                                                                                  │
                                                                                  ▼
                                                                       [ Operationalize Rules ]
                                                                       (Map to MITRE ATT&CK)
                                                                                  │
========================================================================================          │
TIER 2: THE AUTONOMOUS PRODUCTION SOAR ENGINE (WAZUH ──▶ SPLUNK ──▶ LANGGRAPH)           │
========================================================================================          │
                                                                                  │
 [ Live Production Host ] ◀───────────────────────────────────────────────────────┼────────┘
            │                                                                     │
            ▼                                                                     ▼
     [ Wazuh EDR ] ──(Alert Triggered)──▶ [ Python Log Orchestrator ] ◀───[ Custom Telemetry ]
   (Live FIM/Auth Logs)                   (Intercepts Raw JSON Stream)    (Docker Network Metrics)
                                                       │
                           ┌───────────────────────────┴───────────────────────────┐
                           ▼                                                       ▼
                 [ Splunk HEC SIEM ]                                     [ GitHub Audit Ledger ]
               (Forensics & Dashboards)                                (Immutable State Record)
                                                                                   │
                                                                                   ▼
                                                                        [ LangGraph Agent Brain ]
                                                                        (Deterministic State Machine)
                                                                                   │
                             ┌─────────────────────┬───────────────────────────────┤
                             ▼                     ▼                               ▼
                     [ Ingestion Node ]   [ Intel Enrichment ]           [ Remediation Architect ]
                     (Classify Threat)   (AbuseIPDB & CSV Lookups)       (Verify Guardrails & Allowlist)
                                                                                   │
                                                                                   ▼
                                                                         [ Claude AI Analyst ]
                                                                       (Generate Safe Command String)
                                                                                   │
                                                                                   ▼
 [ Live Production Host ] ◀──(Mitigation Applied)─────────────────────────[ Active Response Agent ]
   (IPTables Drop / Chmod)                                                (Closed-Loop Containment)