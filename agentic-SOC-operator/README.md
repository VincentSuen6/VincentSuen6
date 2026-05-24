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


========================================================================================
TIER 3: THE ENTERPRISE DISTRIBUTED SOAR CLUSTER (NEXUSSOAR)
========================================================================================

  [ STEP 1: HYDRA ATTACK ]
           │
           ▼  (SSH Log Event)
  [ STEP 2: FASTAPI INTAKE ]
           │
           ├──► (Sigma String Filter Match?)─────────────[YES]──► [ DROP & INCREMENT COUNTER ]
           │
           ├──► (Redis Check: Has this exact ID fired in last 10m?)──[YES]──► [ DROP & INCREMENT COUNTER ]
           │
           └──► (Is it Brute Force with < 3 retries?)───[YES]──► [ DROP & INCREMENT COUNTER ]
                          │
                         [NO]
                          │
                          ▼
  [ STEP 3: CELERY EVENT DISPATCH ]
           │
           └──► (Async Push to RabbitMQ Broker)
                          │
                          ▼  (Task picked up by Worker)
  [ STEP 4: QDRANT SEMANTIC CLUSTERING ]
  (90% cosine-similar to an event in the last 10-min lookback window?)
           │
     ┌─────┴─────┐
    [YES]        [NO]
     │            │
     ▼            ▼
  [ APPEND TO     [ STEP 5: INITIALIZE 4-NODE LANGGRAPH ]
  MASTER INCIDENT          │
  & DROP WORKFLOW ]        ▼
                  [ Node 1: VirusTotal Threat Intel Lookup ]
                  (0–10 risk score from malicious vendor count)
                           │
                           ▼
                  [ Node 2: MITRE ATT&CK Map Tagging ]
                  (Keyword scan → T-code list or T1078 catch-all)
                           │
                           ▼
                  [ Conditional Risk Router ]
                  (Score >= 7.5? ──[HIGH]──► containment path)
                  (Score <  7.5? ──[LOW]───► audit-only path)
                           │
                           ▼
  [ STEP 6: STATE FREEZE / PAUSE ]
  (LangGraph interrupt_before checkpoint written to PostgreSQL)
           │
           ▼
  [ STEP 7: LIVE SSE DISPATCH ]
  (Dashboard SSE stream surfaces interactive HITL card within 2 seconds)
           │
     ┌─────┴──────────────────┐
  [ APPROVE ]             [ DENY ]
     │                       │
     ▼                       ▼
  [ STEP 8:             [ STEP 8:
  RESUME WORKFLOW ]     INJECT OVERRIDE STATE ]
     │                  (update_state as_node=active_containment
     │                   remediation_action = DENIED_BY_HUMAN)
     │                       │
     ▼                       ▼
  [ Node 3:             [ Node 4:
  Active Containment ]  Splunk Audit Sync ]
  (Array-form iptables       │
   DROP — no shell interp)   ▼
     │                  [ FINISH / END ]
     ▼
  [ Node 4: Splunk HEC Audit Sync ]
  (Circular buffer → Redis + optional HEC POST)
     │
     ▼
  [ FINISH / END ]


========================================================================================
ENTERPRISE GAP ANALYSIS — WHAT BRIDGES LAB TO PRODUCTION
========================================================================================

The tiers above demonstrate the core loop. Below is the roadmap a senior
researcher would execute to harden this into a production-grade MSSP platform.

┌─────────────────────────────────────────────────────────────────────────────────────┐
│  1. OBSERVABILITY — "You can't defend what you can't measure"                       │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Gap: The pipeline has no distributed tracing. A slow VT call, a Qdrant timeout,   │
│  or a stalled Celery task is invisible — you find out when the dashboard freezes.   │
│                                                                                     │
│  Fix: Instrument every LangGraph node with OpenTelemetry span boundaries.           │
│  Export to Jaeger or Grafana Tempo. Add a Prometheus /metrics endpoint to           │
│  app.py exposing queue depth, MTTD, MTTR, containment rate, and false-positive      │
│  rate. Wire a Grafana dashboard so on-call can see pipeline health in one view.     │
│                                                                                     │
│  Industry reference: Palo Alto Cortex XSOAR ships OTel traces as a first-class     │
│  feature in every playbook run.                                                     │
│                                                                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  2. DETECTION QUALITY — "Rules decay. Feedback loops don't."                        │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Gap: Every HITL Deny decision is a confirmed false positive, but that signal       │
│  is discarded. The VT threshold (7.5) never adjusts. Sigma noise lists are static   │
│  and go stale as application logs change.                                           │
│                                                                                     │
│  Fix:                                                                               │
│  a) Persist DENY decisions with alert metadata in a PostgreSQL feedback table.      │
│     After 10+ denies on a pattern, auto-raise the score threshold or add to         │
│     Sigma noise list via PR.                                                        │
│  b) Auto-generate Sigma rules from confirmed true-positive clusters using Claude    │
│     — analyst approves the rule in GitHub, CI deploys it to all three SIEMs.       │
│  c) Add allow-list: known pentest contractor IPs, internal scanners, monitoring     │
│     agents — block immediately suppressed before Tier 1 even runs.                 │
│                                                                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  3. RESILIENCE — "The broker will go down during an active incident."               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Gap: If RabbitMQ drops, app.py returns 500. If VT is rate-limited, the Celery     │
│  task retries with backoff but there is no dead-letter queue — a poison-pill alert  │
│  exhausts all 3 retries and disappears silently.                                    │
│                                                                                     │
│  Fix:                                                                               │
│  a) Declare a dead-letter exchange in docker-compose.yml. Failed tasks land in      │
│     soar_event_stream.dlq and generate a WARNING metric and Discord ping.           │
│  b) Wrap the VT httpx call in a tenacity circuit breaker: after 5 consecutive       │
│     timeouts, short-circuit for 60 seconds and serve the baseline score —           │
│     VT outage does not cascade into HITL backlog.                                   │
│  c) Run 2 api-server replicas behind a lightweight nginx upstream. RabbitMQ         │
│     is already durable (persistent queues) so the broker restart gap is <10s.      │
│                                                                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  4. THREAT INTELLIGENCE DEPTH — "One source is a data point. Six is a verdict."    │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Gap: Node 1 queries VirusTotal IP endpoint only. File hashes, CVE IDs, and        │
│  domain indicators are ignored. OTX, Shodan, MISP, and TAXII/STIX feeds in         │
│  enrichment_engine.py are not called from the NexusSOAR graph.                     │
│                                                                                     │
│  Fix:                                                                               │
│  a) Promote enrichment_engine.enrich_threat() into Node 1, replacing the           │
│     single VT call. All 6 sources degrade gracefully on missing keys.              │
│  b) Export confirmed IOCs (IP, hash, domain) as STIX 2.1 bundles to a TAXII        │
│     server so downstream consumers (MSSP clients, partner SIEMs) auto-receive      │
│     your threat context without manual sharing.                                     │
│  c) Implement IOC lifecycle TTL: automatically retire indicators after 30 days      │
│     unless re-confirmed, preventing stale blocks from affecting legitimate IPs.     │
│                                                                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  5. CASE MANAGEMENT — "Slack pings are not an incident record."                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Gap: Incidents surface as Discord embeds and Redis circular buffers. There is      │
│  no persistent case, no analyst assignment, no SLA tracking, and no closure         │
│  state. MTTD and MTTR are unmeasurable.                                             │
│                                                                                     │
│  Fix: After Node 2 (MITRE map), open a case in TheHive or Jira Service             │
│  Management via REST API. Attach the full enrichment blob, MITRE chain, and         │
│  VT score. Set SLA timer. On HITL approval, update case status to Contained.       │
│  On DENY, update to False Positive. Export weekly MTTD/MTTR report as KPI.        │
│                                                                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  6. COMPLIANCE — "Audit logs that can be deleted are not audit logs."               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Gap: audit_trail.jsonl and the Redis circular buffer are mutable. An attacker      │
│  with write access to the SOAR host can delete evidence. PII (analyst usernames,   │
│  IP addresses of internal users) may appear in audit records without scrubbing.    │
│                                                                                     │
│  Fix:                                                                               │
│  a) Append audit entries to an S3 bucket with Object Lock (WORM) enabled or        │
│     to a Merkle-chained PostgreSQL table where each row hashes the previous row.   │
│  b) Run PII scrubbing on audit records before persistence: redact internal IP       │
│     ranges (RFC 1918) and analyst email addresses from the event blob.              │
│  c) Version-control every SOAR playbook change in git. CI validates that no         │
│     playbook bypasses the HITL gate for CRITICAL severity events.                  │
│                                                                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  7. RESPONSE BREADTH — "iptables on one host is not network containment."           │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Gap: Active containment issues iptables only on the worker container host.         │
│  A lateral-moving attacker who has already pivoted to a second host is not         │
│  blocked. Cloud-origin attacks bypass perimeter iptables entirely.                 │
│                                                                                     │
│  Fix:                                                                               │
│  a) Add a firewall API containment path alongside iptables: call Palo Alto          │
│     PAN-OS API or pfSense REST API to push a deny rule at the network edge —       │
│     blocks all hosts simultaneously, not just the SOAR worker.                     │
│  b) For cloud-origin attacks, call Cloudflare/AWS WAF IP block API so the block    │
│     lands at the edge CDN layer before traffic reaches any host.                   │
│  c) Trigger a Velociraptor artifact collection on the target host when              │
│     containment is approved — memory dump, running processes, open connections,    │
│     recent file writes. Preserves forensic evidence before the attacker's          │
│     cleanup scripts run.                                                            │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

IMPLEMENTATION PRIORITY ORDER (by impact / effort ratio):
  P0 — Dead-letter queue + circuit breaker        (resilience, 2h)
  P0 — OTel tracing per LangGraph node            (observability, 4h)
  P1 — TheHive/Jira case creation after Node 2    (case management, 1 day)
  P1 — HITL deny → feedback table → threshold adj (detection quality, 1 day)
  P2 — STIX 2.1 IOC export + TAXII endpoint       (threat intel depth, 2 days)
  P2 — Firewall API containment (PAN-OS/pfSense)  (response breadth, 2 days)
  P3 — Merkle-chained audit log + PII scrubbing   (compliance, 3 days)
  P3 — Velociraptor forensic collection trigger   (response breadth, 3 days)

