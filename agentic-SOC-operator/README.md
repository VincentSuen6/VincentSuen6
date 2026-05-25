# [Agentic SOAR — The Agentic SOC Automation Engine](https://github.com/VincentSuen6/agentic-SOC-operator)

A three-tier, production-grade Security Orchestration, Automation and Response platform.
Tier 1 is a detection engineering lab built on Elastic SIEM. Tier 2 is an autonomous
pipeline (Wazuh → Splunk → LangGraph). Tier 3 is an enterprise distributed cluster with
semantic deduplication, PostgreSQL HITL state, and a real-time Next.js operator dashboard.

───────────────────────────────────────────────────────────────────────────────────────────
TIER 1 — RESEARCH & DETECTION ENGINEERING LAB (ELASTIC SIEM)
───────────────────────────────────────────────────────────────────────────────────────────

  [ Threat Emulation ]──▶[ Target Victim VM ]──▶[ Elastic Agent ]──▶[ Elastic Cloud SIEM ]
    (Parrot OS / Kali)     (Win 11 / Ubuntu)      (Sysmon & Zeek)    (Extract IOCs & TTPs)
                                                                              │
                                                                              ▼
                                                                   [ Operationalize Rules ]
                                                                   (Map to MITRE ATT&CK)
                                                                              │
                                                                              ▼
                                                                    [ Detections flow to
                                                                       Tier 2 below ]


───────────────────────────────────────────────────────────────────────────────────────────
TIER 2 — AUTONOMOUS PRODUCTION SOAR ENGINE (WAZUH ──▶ SPLUNK ──▶ LANGGRAPH)
───────────────────────────────────────────────────────────────────────────────────────────

  [ Live Production Host ]        [ Custom Telemetry ]         (Elastic detections
         │                         (Docker Metrics)              from Tier 1)
         ▼                                │                            │
  [ Wazuh EDR ]──(Alert)──▶[ Python Log Orchestrator ]◀──────────────┘
  (FIM / Auth Logs)          (Intercepts Raw JSON Stream)
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
          [ Splunk HEC SIEM ]                       [ GitHub Audit Ledger ]
          (Forensics & Dashboards)                  (Immutable State Record)
                                                               │
                                                               ▼
                                                    [ LangGraph Agent Brain ]
                                                    (Deterministic State Machine)
                                                               │
                          ┌────────────────────┬──────────────┘
                          ▼                    ▼              ▼
                  [ Ingestion Node ]  [ Intel Enrichment ] [ Remediation Architect ]
                  (Classify Threat)  (AbuseIPDB / CSV)    (Guardrails & Allowlist)
                                                                    │
                                                                    ▼
                                                         [ Claude AI Analyst ]
                                                         (Generate Safe Command)
                                                                    │
                                                                    ▼
  [ Live Production Host ]◀────────(Mitigation Applied)────[ Active Response Agent ]
  (IPTables Drop / Chmod)                                  (Closed-Loop Containment)


───────────────────────────────────────────────────────────────────────────────────────────
TIER 3 — ENTERPRISE DISTRIBUTED SOAR CLUSTER
───────────────────────────────────────────────────────────────────────────────────────────

  [ STEP 1: ATTACKER ]
  (Hydra SSH brute-force / Suricata alert / Wazuh webhook)
           │
           ▼
  [ STEP 2: FASTAPI INGESTION GATEWAY ]  ← 500/min rate limit (slowapi)
           │
           ├──▶ Sigma noise match?          [YES]──▶ DROP  (pure CPU — zero I/O)
           │
           ├──▶ Redis dedup: seen in 10m?   [YES]──▶ DROP  (one EXISTS check)
           │
           └──▶ Brute-force < 3 attempts?  [YES]──▶ DROP  (risk threshold)
                          │
                         [NO — unique, above threshold]
                          │
                          ▼
  [ STEP 3: RABBITMQ EVENT BUS ]
  (Durable queue — alert survives broker restart)
           │
           ▼
  [ STEP 4: SEMANTIC DEDUPLICATION WORKER ]  (workers.py)
  (all-MiniLM-L6-v2 → 384-dim vector → Qdrant cosine search)
  (10-minute lookback enforced via timestamp payload filter)
           │
     ┌─────┴──────┐
    [≥ 90%]    [Unique]
     │              │
     ▼              ▼
  Bundle into   [ STEP 5: 4-NODE LANGGRAPH STATE MACHINE ]  (tasks.py)
  master INC            │
  and drop              ▼
                [ Node 1: 6-Source Threat Intel ]
                (AbuseIPDB · VirusTotal · OTX · Shodan · MISP — parallel fan-out)
                (Composite 0–10 score  |  internal blacklist → instant 10.0)
                        │
                        ▼
                [ Node 2: MITRE ATT&CK Mapping ]
                (Keyword scan → T-code list or T1078 catch-all)
                        │
                        ▼
                [ Adaptive Risk Router ]
                (Threshold read from Redis — adjusts after DENY feedback)
                        │
           ┌────────────┴────────────┐
       [≥ 7.5]                   [< 7.5]
           │                         │
           ▼                         ▼
  [ STEP 6: HITL STATE FREEZE ]   [ Skip to Node 4 ]
  (interrupt_before serialized              │
   to PostgreSQL checkpoint)               │
           │                              │
           ▼                              │
  [ STEP 7: SSE PUSH ]                    │
  (HITL card on dashboard < 2s)           │
           │                              │
     ┌─────┴──────────┐                  │
  [APPROVE]        [DENY]                 │
     │                │                  │
     ▼                ▼                  │
  Resume          Inject override         │
  workflow        (DENIED_BY_HUMAN)       │
     │           feedback.record()        │
     │           raises threshold         │
     │                │                  │
     ▼                ▼                  │
  [ Node 3: Active Containment ]         │
  (iptables DROP — array form,           │
   IP validated, DRY_RUN guard)          │
     │                │                  │
     └────────┬───────┘                  │
              │◀─────────────────────────┘
              ▼
  [ Node 4: Merkle-Chained Audit ]
  (SHA-256 chain in PostgreSQL · PII scrubbed · optional Splunk HEC POST)
              │
              ▼
         [ END ]


───────────────────────────────────────────────────────────────────────────────────────────
ENTERPRISE GAP ANALYSIS — BRIDGING LAB TO PRODUCTION
───────────────────────────────────────────────────────────────────────────────────────────

The tiers above show the core loop. Below is the roadmap a senior researcher executes to
harden this into a production-grade MSSP platform. Items marked ✅ are implemented.

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│  1. OBSERVABILITY  ✅ IMPLEMENTED                                                       │
│  "You can't defend what you can't measure."                                             │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Every LangGraph node is wrapped in an OpenTelemetry span exported to Jaeger via        │
│  OTLP gRPC. A _NoopTracer fallback ensures the pipeline runs in CI without Jaeger.      │
│  The /metrics endpoint on api-server exposes Prometheus text consumed by Grafana:       │
│                                                                                         │
│    soar_alerts_total{level="warning"}   — triaged alert count                           │
│    soar_containments_total              — IPs blocked via iptables                      │
│    soar_hitl_pending                    — queue depth of pending approvals              │
│    soar_detection_threshold             — live adaptive routing threshold               │
│                                                                                         │
│  Industry reference: Palo Alto Cortex XSOAR ships OTel traces as a first-class         │
│  feature in every playbook run.                                                         │
│                                                                                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  2. DETECTION QUALITY  ✅ IMPLEMENTED                                                   │
│  "Rules decay. Feedback loops don't."                                                   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Every HITL Deny click is persisted to the hitl_feedback PostgreSQL table.              │
│  After every 5 denies on the same alert_type, the routing threshold rises +0.5          │
│  (written to Redis — no worker restart required). After 10 denies, Claude Haiku         │
│  reads the 10 most recent false-positive raw logs and generates a Sigma suppression     │
│  rule written to SIEM-Detection/sigma/candidates/ for analyst review before CI deploy.  │
│                                                                                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  3. RESILIENCE  🔲 NEXT UP                                                              │
│  "The broker will go down during an active incident."                                   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Gap: If RabbitMQ drops, app.py returns 500. A poison-pill alert exhausts all 3         │
│  Celery retries and disappears silently. VT rate-limiting cascades into HITL backlog.   │
│                                                                                         │
│  Fix:                                                                                   │
│  a) Declare a dead-letter exchange in docker-compose.yml. Failed tasks land in          │
│     soar_event_stream.dlq and increment a WARNING metric.                               │
│  b) Wrap the VT call in a tenacity circuit breaker: 5 consecutive timeouts →            │
│     short-circuit 60s and serve baseline score instead of failing the task.             │
│  c) Run 2 api-server replicas behind nginx. RabbitMQ uses durable queues so            │
│     the broker restart gap is < 10s.                                                    │
│                                                                                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  4. THREAT INTELLIGENCE DEPTH  ✅ IMPLEMENTED                                           │
│  "One source is a data point. Six is a verdict."                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Node 1 fans out to AbuseIPDB, VirusTotal, OTX AlienVault, Shodan, and MISP in         │
│  parallel using ThreadPoolExecutor. Total latency = max(source_timeouts), not sum.      │
│  A missing API key degrades that source to {} — the composite score uses what's left.  │
│  Internal blacklist check is instant (no network) and overrides to 10.0.               │
│                                                                                         │
│  Composite scoring (max 10.0):                                                          │
│    AbuseIPDB confidence : up to 3.0 pts     OTX pulse count : up to 2.0 pts            │
│    AbuseIPDB TOR flag   : +1.0 pt           Shodan CVEs     : up to 1.5 pts            │
│    VirusTotal malicious : up to 2.0 pts     MISP hits       : up to 1.0 pt             │
│                                                                                         │
│  Remaining: STIX 2.1 IOC export + TAXII endpoint for downstream MSSP sharing.          │
│                                                                                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  5. CASE MANAGEMENT  🔲 PLANNED                                                         │
│  "Slack pings are not an incident record."                                              │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Gap: No persistent case, no analyst assignment, no SLA tracking, no closure state.    │
│  MTTD and MTTR are unmeasurable.                                                        │
│                                                                                         │
│  Fix: After Node 2, open a case in TheHive or Jira Service Management. Attach the      │
│  full enrichment blob, MITRE chain, and score. Set SLA timer. On approval, update      │
│  to Contained. On deny, update to False Positive. Export weekly MTTD/MTTR as KPI.     │
│                                                                                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  6. COMPLIANCE  ✅ IMPLEMENTED                                                          │
│  "Audit logs that can be deleted are not audit logs."                                   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Every audit record is SHA-256 hashed with the previous row's hash:                    │
│    row_hash = SHA256(seq | logged_at | incident_id | event_json | prev_hash)           │
│  Tampering with any row breaks every downstream hash — detectable by audit_verify().   │
│  PII scrubbing removes RFC 1918 IPs and email addresses before persistence.             │
│  The first record uses SHA256("GENESIS") as its anchor.                                 │
│                                                                                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  7. RESPONSE BREADTH  🔲 PLANNED                                                        │
│  "iptables on one host is not network containment."                                     │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Gap: Active containment only blocks on the worker container host. A lateral-moving    │
│  attacker who has already pivoted is not blocked. Cloud-origin attacks bypass it.      │
│                                                                                         │
│  Fix:                                                                                   │
│  a) Firewall API path: call Palo Alto PAN-OS API or pfSense REST to push a deny        │
│     rule at the network edge — blocks all hosts simultaneously.                         │
│  b) Cloud-origin: call Cloudflare / AWS WAF IP block API so the block lands at the     │
│     CDN layer before traffic reaches any host.                                          │
│  c) Trigger Velociraptor artifact collection on the target host at containment —        │
│     memory dump, open connections, recent file writes — before attacker cleanup runs.  │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘


───────────────────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION STATUS
───────────────────────────────────────────────────────────────────────────────────────────

  ✅  6-source parallel threat intel      intel.py        AbuseIPDB/VT/OTX/Shodan/MISP
  ✅  Merkle-chained audit + PII scrub    audit.py        SHA-256 chain, RFC1918 redaction
  ✅  Adaptive HITL feedback loop         feedback.py     PostgreSQL table, Sigma gen
  ✅  OTel tracing on all 4 nodes         tasks.py        Jaeger waterfall, noop fallback
  ✅  Prometheus /metrics endpoint        app.py          4 counters + live threshold gauge
  ✅  PostgreSQL HITL checkpointing       tasks.py        interrupt_before, resume/deny
  ✅  Semantic deduplication              workers.py      Qdrant cosine, 10-min window
  ✅  DRY_RUN fast-path guard             workers.py      IP validation + RFC1918 check
  🔲  Dead-letter queue + circuit breaker                 RabbitMQ DLX + tenacity
  🔲  TheHive / Jira case management                      Case open after Node 2
  🔲  STIX 2.1 IOC export + TAXII                         Downstream MSSP sharing
  🔲  Firewall API containment                            PAN-OS / pfSense / AWS WAF
  🔲  Velociraptor forensic collection                    Memory dump at containment


───────────────────────────────────────────────────────────────────────────────────────────
QUICKSTART — UBUNTU / DEBIAN
───────────────────────────────────────────────────────────────────────────────────────────

Prerequisites
  Docker >= 24.0  |  docker compose >= 2.27  |  Node.js >= 20 (dashboard only)
  API keys are optional — each intel source degrades to {} if its key is absent.

Step 1 — Configure
  git clone https://github.com/VincentSuen6/agentic-SOC-operator.git
  cd agentic-SOC-operator/soar
  cp .env.example .env
  # Fill in any keys you have. DRY_RUN=true is the safe default — no live iptables.

Step 2 — Launch (8 containers)
  docker compose up --build -d
  docker compose ps
  # broker · cache · postgres · qdrant · jaeger · api-server · worker · semantic-worker

Step 3 — Verify
  curl  http://localhost:8000/health          # {"status":"ok"}
  curl  http://localhost:8000/metrics         # Prometheus text
  open  http://localhost:15672               # RabbitMQ UI  (guest / guest)
  open  http://localhost:16686               # Jaeger trace waterfall
  open  http://localhost:6334/dashboard      # Qdrant vector browser

Step 4 — Dashboard
  cd soar-dashboard
  npm install
  NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
  open  http://localhost:3000

Step 5 — Fire a test alert
  curl -X POST http://localhost:8000/api/v1/ingest \
    -H "Content-Type: application/json" \
    -d '{
      "alert_id":        "TEST-001",
      "vendor":          "Wazuh",
      "alert_type":      "Brute Force",
      "source_ip":       "45.142.212.100",
      "target_host":     "PROD_SERVER_01",
      "failed_attempts": 14,
      "raw_log":         "Failed password for root from 45.142.212.100 port 22 ssh2"
    }'
  # 45.142.212.100 is in the internal blacklist → score 10.0 → HITL card appears.
  # Approve or Deny at http://localhost:3000
  # View the trace waterfall at http://localhost:16686 (service: soar.pipeline)

Environment variables (.env.example)
  DRY_RUN=true                               # false = live iptables (opt-in)
  THREAT_SCORE_THRESHOLD=7.5                 # starting point — adaptive loop adjusts it
  BLOCKED_IP_TTL_SECONDS=86400
  VT_API_KEY=                                # VirusTotal free: 4 req/min
  ABUSEIPDB_KEY=                             # AbuseIPDB free: 1000 req/day
  OTX_API_KEY=                               # AlienVault OTX: free
  SHODAN_API_KEY=                            # Shodan: paid; omit to skip
  MISP_URL=                                  # Your MISP instance; omit to skip
  MISP_KEY=
  ANTHROPIC_API_KEY=                         # Sigma rule generation in feedback.py
  SPLUNK_HEC_URL=                            # Optional HEC endpoint
  SPLUNK_HEC_TOKEN=
  POSTGRES_CONN=postgresql://soar:soar@postgres:5432/soar
  CELERY_BROKER_URL=amqp://broker:5672//
  REDIS_URL=redis://cache:6379/0
  OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
