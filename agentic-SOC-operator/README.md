# [Agentic SOAR — The Agentic SOC Automation Engine](https://github.com/VincentSuen6/agentic-SOC-operator)

A three-tier, production-grade Security Orchestration, Automation and Response platform.
Tier 1 is a detection engineering lab on Elastic SIEM. Tier 2 is an autonomous pipeline
(Wazuh → Splunk → LangGraph). Tier 3 is an enterprise distributed cluster with semantic
deduplication, PostgreSQL HITL state, OTel tracing, and a real-time Next.js operator dashboard.

---

## Architecture

### Tier 1 — Research & Detection Engineering Lab (Elastic SIEM)

```
  [ Threat Emulation ] ──▶ [ Target Victim VM ] ──▶ [ Elastic Agent ] ──▶ [ Elastic Cloud SIEM ]
    (Parrot OS / Kali)       (Win 11 / Ubuntu)        (Sysmon & Zeek)      (Extract IOCs & TTPs)
                                                                                    │
                                                                                    ▼
                                                                         [ Operationalize Rules ]
                                                                         (Map to MITRE ATT&CK)
                                                                                    │
                                                                                    ▼
                                                                           [ Feeds into Tier 2 ]
```

---

### Tier 2 — Autonomous Production SOAR Engine (Wazuh → Splunk → LangGraph)

```
  ┌─ Elastic Tier 1 detections + raw telemetry ───────────────────────────────────────────────┐
  │                                                                                            │
  │  [ Live Production Host ]      [ Custom Telemetry ]                                       │
  │          │                      (Docker Metrics)                                          │
  │          ▼                             │                                                  │
  │  [ Wazuh EDR ] ──(Alert)──▶ [ Python Log Orchestrator ] ◀─────────────────────────────── ┘
  │  (FIM / Auth Logs)            (Intercepts Raw JSON Stream)
  │                                        │
  │                     ┌──────────────────┴──────────────────┐
  │                     ▼                                     ▼
  │           [ Splunk HEC SIEM ]                 [ GitHub Audit Ledger ]
  │           (Forensics & Dashboards)            (Immutable State Record)
  │                                                           │
  │                                                           ▼
  │                                                [ LangGraph Agent Brain ]
  │                                                (Deterministic State Machine)
  │                                                           │
  │                     ┌────────────────────┬───────────────┘
  │                     ▼                    ▼                ▼
  │             [ Ingestion Node ] [ Intel Enrichment ] [ Remediation Architect ]
  │             (Classify Threat)  (AbuseIPDB / CSV)   (Guardrails & Allowlist)
  │                                                           │
  │                                                           ▼
  │                                                  [ Claude AI Analyst ]
  │                                                  (Generate Safe Command)
  │                                                           │
  │                                                           ▼
  └▶ [ Live Production Host ] ◀────(Mitigation Applied)──[ Active Response Agent ]
     (IPTables Drop / Chmod)                                (Closed-Loop Containment)
```

---

### Tier 3 — Enterprise Distributed SOAR Cluster

```
  [ ATTACKER ]
  (Hydra SSH brute-force / Suricata / Wazuh webhook)
          │
          ▼
  ┌─────────────────────────────────────────────┐
  │  FASTAPI INGESTION GATEWAY  (app.py)        │  ← 500 req/min rate limit
  │                                             │
  │  Tier 1 ── Sigma noise match?        [YES] ─┼──▶ DROP   (pure CPU, zero I/O)
  │  Tier 2 ── Redis dedup: seen in 10m? [YES] ─┼──▶ DROP   (one EXISTS check)
  │  Tier 3 ── Brute-force < 3 attempts? [YES] ─┼──▶ DROP   (risk threshold)
  └──────────────────────┬──────────────────────┘
                        [NO — unique, above threshold]
                         │
                         ▼
  [ RABBITMQ EVENT BUS ]
  (Durable queue — alert survives broker restart)
                         │
                         ▼
  ┌─────────────────────────────────────────────┐
  │  SEMANTIC DEDUPLICATION  (workers.py)       │
  │  all-MiniLM-L6-v2 → 384-dim vector         │
  │  Qdrant cosine search, 10-min lookback      │
  └──────────────┬──────────────────────────────┘
                 │
        ┌────────┴────────┐
      [≥ 90%]          [Unique]
        │                  │
        ▼                  ▼
  Bundle into      ┌──────────────────────────────────────┐
  master INC       │  4-NODE LANGGRAPH  (tasks.py)        │
  and discard      │                                      │
                   │  Node 1: 6-Source Threat Intel       │
                   │  AbuseIPDB · VT · OTX · Shodan · MISP│
                   │  Parallel fan-out · composite 0–10   │
                   │  Internal blacklist → instant 10.0   │
                   │            │                         │
                   │            ▼                         │
                   │  Node 2: MITRE ATT&CK Mapping        │
                   │  Keyword scan → T-codes or T1078     │
                   │            │                         │
                   │            ▼                         │
                   │  Adaptive Risk Router                 │
                   │  (Redis threshold — feedback-driven) │
                   └────────────┬─────────────────────────┘
                                │
                    ┌───────────┴────────────┐
                 [≥ 7.5]                  [< 7.5]
                    │                        │
                    ▼                        │
          ┌──────────────────┐              │
          │  HITL STATE      │              │
          │  FREEZE          │              │
          │  PostgreSQL      │              │
          │  checkpoint      │              │
          └────────┬─────────┘              │
                   │                        │
                   ▼                        │
          SSE push to dashboard             │
          (HITL card appears < 2s)          │
                   │                        │
          ┌────────┴────────┐              │
       [APPROVE]         [DENY]             │
          │                 │               │
          ▼                 ▼               │
       Resume          Inject override      │
       workflow        DENIED_BY_HUMAN      │
                       feedback.record()    │
                       raises threshold     │
          │                 │               │
          ▼                 │               │
  Node 3: Active            │               │
  Containment               │               │
  (iptables DROP,           │               │
   DRY_RUN guard,           │               │
   IP validated)            │               │
          │                 │               │
          └────────┬────────┘               │
                   │◀───────────────────────┘
                   ▼
          Node 4: Merkle-Chained Audit
          SHA-256 chain · PII scrub
          PostgreSQL · optional Splunk HEC
                   │
                   ▼
                [ END ]
```

---

## Enterprise Hardening Roadmap

### 1. Observability — ✅ Implemented

Every LangGraph node is wrapped in an OpenTelemetry span exported to Jaeger via OTLP gRPC.
A `_NoopTracer` fallback ensures the pipeline runs in CI without a full Docker stack.
The `/metrics` endpoint on `api-server` exposes Prometheus text:

- `soar_alerts_total{level="warning"}` — triaged alert count
- `soar_containments_total` — IPs blocked via iptables
- `soar_hitl_pending` — queue depth of pending approvals
- `soar_detection_threshold` — live adaptive routing threshold (updates as feedback adjusts it)

> **Industry reference:** Palo Alto Cortex XSOAR ships OTel traces as a first-class feature in every playbook run.

---

### 2. Detection Quality — ✅ Implemented

Every HITL Deny click is persisted to the `hitl_feedback` PostgreSQL table.

- Every **5 denies** on the same `alert_type` → threshold rises +0.5 (written to Redis, no worker restart needed)
- Every **10 denies** → Claude Haiku reads the 10 most recent false-positive raw logs and generates a Sigma suppression YAML, written to `SIEM-Detection/sigma/candidates/` for analyst review before CI deploy

---

### 3. Resilience — 🔲 Planned

**Gap:** A poison-pill alert exhausts all 3 Celery retries and disappears silently. VT rate-limiting cascades into a HITL backlog with no visibility.

**Fix:**
- Declare a dead-letter exchange in `docker-compose.yml`. Failed tasks land in `soar_event_stream.dlq` and increment a WARNING metric
- Wrap the VT call in a `tenacity` circuit breaker: 5 consecutive timeouts → short-circuit 60s and serve baseline score
- Run 2 `api-server` replicas behind nginx (RabbitMQ already uses durable queues)

---

### 4. Threat Intelligence Depth — ✅ Implemented

Node 1 fans out to **five sources in parallel** using `ThreadPoolExecutor`. Total latency = `max(timeouts)`, not sum. A missing API key degrades that source to `{}` — the composite score uses what's available.

| Source | Contribution | Max Points |
|---|---|---|
| AbuseIPDB confidence | `score/100 × 3.0` | 3.0 |
| AbuseIPDB TOR flag | flat bonus | 1.0 |
| VirusTotal malicious | `vendors/90 × 2.0` | 2.0 |
| OTX AlienVault pulses | `count × 0.2` | 2.0 |
| Shodan exposed CVEs | `count × 0.3` | 1.5 |
| MISP attribute hits | `count × 0.25` | 1.0 |

**Remaining:** STIX 2.1 IOC export + TAXII endpoint for downstream MSSP sharing.

---

### 5. Case Management — 🔲 Planned

**Gap:** No persistent case, no analyst assignment, no SLA tracking, no closure state. MTTD and MTTR are unmeasurable.

**Fix:** After Node 2, open a case in TheHive or Jira Service Management via REST. Attach enrichment blob, MITRE chain, and score. On approval → Contained. On deny → False Positive. Export weekly MTTD/MTTR as KPI.

---

### 6. Compliance — ✅ Implemented

Every audit record is SHA-256 hashed with the previous row's hash:

```
row_hash = SHA256( seq | logged_at | incident_id | event_json | prev_hash )
```

Tampering with any row breaks every downstream hash — detected by `audit_verify()`. PII scrubbing removes RFC 1918 addresses and email patterns before persistence. The chain anchors at `SHA256("GENESIS")`.

---

### 7. Response Breadth — 🔲 Planned

**Gap:** `iptables` only blocks on the worker container host. A lateral-moving attacker who has already pivoted is not blocked.

**Fix:**
- Call PAN-OS API or pfSense REST to push a deny rule at the network edge — blocks all hosts simultaneously
- Call Cloudflare / AWS WAF IP block API for cloud-origin attacks
- Trigger Velociraptor artifact collection at containment time (memory dump, open connections, recent writes)

---

## Implementation Status

| Feature | Status | File |
|---|---|---|
| 6-source parallel threat intel | ✅ | `intel.py` |
| Merkle-chained audit + PII scrub | ✅ | `audit.py` |
| Adaptive HITL feedback loop | ✅ | `feedback.py` |
| OTel tracing on all 4 nodes | ✅ | `tasks.py` |
| Prometheus `/metrics` endpoint | ✅ | `app.py` |
| PostgreSQL HITL checkpointing | ✅ | `tasks.py` |
| Semantic deduplication | ✅ | `workers.py` |
| DRY_RUN fast-path guard + IP validation | ✅ | `workers.py` |
| Dead-letter queue + circuit breaker | 🔲 | — |
| TheHive / Jira case management | 🔲 | — |
| STIX 2.1 IOC export + TAXII | 🔲 | — |
| Firewall API containment (PAN-OS / AWS WAF) | 🔲 | — |
| Velociraptor forensic collection | 🔲 | — |

---

## Quickstart — Ubuntu / Debian

### Prerequisites

- Docker ≥ 24.0 and docker compose ≥ 2.27
- Node.js ≥ 20 (dashboard only)
- API keys are optional — each intel source returns `{}` if its key is absent

### Step 1 — Clone and configure

```bash
git clone https://github.com/VincentSuen6/agentic-SOC-operator.git
cd agentic-SOC-operator/soar
cp .env.example .env
# Fill in any keys you have. DRY_RUN=true is the safe default — no live iptables.
```

### Step 2 — Launch (8 containers)

```bash
docker compose up --build -d
docker compose ps
# broker · cache · postgres · qdrant · jaeger · api-server · worker · semantic-worker
```

### Step 3 — Verify services

```bash
curl http://localhost:8000/health      # {"status":"ok"}
curl http://localhost:8000/metrics     # Prometheus text output
```

| URL | Service |
|---|---|
| http://localhost:15672 | RabbitMQ UI (guest / guest) |
| http://localhost:16686 | Jaeger trace waterfall |
| http://localhost:6334/dashboard | Qdrant vector browser |
| http://localhost:3000 | Operator dashboard |

### Step 4 — Launch the dashboard

```bash
cd soar-dashboard
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

### Step 5 — Fire a test alert

```bash
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
```

`45.142.212.100` is in the internal blacklist → composite score 10.0 → HITL card appears in the dashboard within 2 seconds. Approve or Deny the containment, then open Jaeger and search `service=soar.pipeline` to see the node-by-node trace waterfall.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DRY_RUN` | `true` | `false` enables live iptables blocks (opt-in) |
| `THREAT_SCORE_THRESHOLD` | `7.5` | Starting threshold — adaptive loop adjusts at runtime |
| `BLOCKED_IP_TTL_SECONDS` | `86400` | How long a blocked IP stays in Redis |
| `VT_API_KEY` | — | VirusTotal free tier: 4 req/min |
| `ABUSEIPDB_KEY` | — | AbuseIPDB free: 1000 req/day |
| `OTX_API_KEY` | — | AlienVault OTX: free |
| `SHODAN_API_KEY` | — | Shodan: paid; omit to skip |
| `MISP_URL` / `MISP_KEY` | — | Your MISP instance; omit to skip |
| `ANTHROPIC_API_KEY` | — | Sigma rule generation in `feedback.py` |
| `SPLUNK_HEC_URL` / `SPLUNK_HEC_TOKEN` | — | Optional HEC audit forward |
| `POSTGRES_CONN` | `postgresql://soar:soar@postgres:5432/soar` | LangGraph checkpoint + audit chain |
| `CELERY_BROKER_URL` | `amqp://broker:5672//` | RabbitMQ connection |
| `REDIS_URL` | `redis://cache:6379/0` | Metrics + dedup cache |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | Jaeger OTLP gRPC receiver |
