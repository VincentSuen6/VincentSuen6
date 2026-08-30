# Hi, I'm Vincent 

## AI Pentester | Security Engineer | Cybersecurity Researcher | CS @ SFU | 

I am a third-year Computing Science student at Simon Fraser University and the External Director of the SFU Cybersecurity Club. My work focuses on the intersection of *Autonomous AI* and *Threat Intelligence*, specifically developing agents that automate vulnerability analysis and incident response.

##  Quick Overview

-  **Research:** Developing autonomous AI agents for threat intelligence using LangGraph and the Anthropic API.
-  **Competitive Excellence:** Placed Top 5 in the BC Region at CyberSci Canada Regionals (2025).
-  **Leadership:** Orchestrating industry partnerships, technical workshops, and sponsorships as External Director of the SFU Cybersecurity Club.
- **Certifications:** ISC2 Certified in Cybersecurity (CC). (CompTIA Security+ and CCNA in progress)

## 🛠️ Technical Arsenal

| Category | Tools & Technologies |
| :--- | :--- |
| **Threat Detection & SIEM** | Splunk (Rule Authoring & Log Correlation), Elastic SIEM, Wazuh EDR, MITRE ATT&CK, TAXII/STIX |
| **Forensics & IR** | Velociraptor DFIR (VQL), Wireshark, Endpoint Triage, Memory Analysis |
| **AI & Data Engineering** | Python (LangGraph, Anthropic API), SQL (BCNF Normalization), Data Pipelines, Redis, RabbitMQ, Qdrant |
| **Vulnerability Mgmt** | BurpSuite, Ghidra, x64dbg, Nmap, CVE Exploit Simulation, ModSecurity WAF |
| **Cloud & DevOps** | Docker, Docker Compose, Linux/Unix SysAdmin, Azure, OpenTelemetry, Jaeger, Prometheus |
| **Red & Purple Team** | OWASP Top 10 Exploitation, WAF Bypass Testing, MITRE ATT&CK Emulation, C2 Frameworks, Frida |

##  Specialized Training & Labs

### Antisyphon Training & Research Labs
- 🔹 **Active Defense:** Implementing tactical deception and monitoring via home-lab environments.
- 🔹 **SOC Operations:** Configured Splunk for security monitoring and detection rule validation across attack simulations.
- 🔹 **Endpoint Telemetry:** Deployed Velociraptor DFIR servers to facilitate real-time forensic collection and VQL-based remote triage.
- 🔹 **Threat Hunting & Modelling:** Leveraged Elastic/Splunk to aggregate telemetry from endpoints, identifying behavioral deviations in user account activity.

---

##  Featured Projects

---

### [Agentic SOAR — The Agentic SOC Automation Engine](https://github.com/VincentSuen6/VincentSuen6/tree/main/agentic-SOC-operator)

A three-tier, production-grade Security Orchestration, Automation and Response (SOAR) platform that takes a security alert from raw telemetry all the way to closed-loop autonomous containment with a cryptographically immutable audit trail.

#### What It Solves
Enterprise SOCs are overwhelmed by alert volume. Analysts waste hours on noise before reaching a genuine threat. This platform eliminates that problem through layered automated triage: a Sigma-rule noise filter, a Redis semantic deduplication cache, and a CVSS threshold gate eliminate false positives before a single LLM token is spent. Only genuinely novel, high-severity threats reach the AI analyst.

#### Architecture — Three Tiers

**Tier 1 — Detection Engineering Lab (Elastic SIEM)**

A realistic adversary emulation environment where attacks are executed from Parrot OS / Kali against Windows 11 and Ubuntu victim VMs instrumented with Elastic Agents (Sysmon + Zeek network capture). Raw telemetry flows into Elastic Cloud SIEM, where Indicators of Compromise (IOCs) and Tactics, Techniques, and Procedures (TTPs) are extracted and operationalized as detection rules mapped to the MITRE ATT&CK framework. Validated rules and their associated alerts feed downstream into Tier 2.

**Tier 2 — Autonomous SOAR Pipeline (Wazuh → Splunk → LangGraph)**

A closed-loop response engine integrating three complementary telemetry sources:

| Source | Detection Scope |
|--------|----------------|
| Wazuh EDR | File Integrity Monitoring, rootkit detection, auth log analysis, process injection |
| Elastic SIEM | Network-level Sysmon events, east-west traffic, lateral movement |
| Docker Metrics | Containerized service telemetry, escape detection, anomalous process spawns |

A Python Log Orchestrator intercepts the raw JSON alert stream and fans it to two sinks simultaneously: a **Splunk HEC client** (for forensic dashboards and saved alert queries) and a **GitHub Audit Ledger** (signed commits forming a tamper-evident forensic record of every autonomous decision). From the ledger, a 6-node **LangGraph state machine** takes over:

1. **Ingestion Node** — classifies threat category and priority
2. **Threat Intel Node** — queries AbuseIPDB and CSV reputation feeds
3. **Remediation Architect** — selects a validated containment strategy against a strict allowlist, rejecting destructive commands below a 0.92 confidence threshold
4. **Claude AI Analyst** — maps observables to CVEs, generates specific `iptables`/`chmod`/`kill` commands with full reasoning
5. **Active Response Agent** — executes the validated command directly on the live production host
6. **Markdown Summary Node** — generates an executive incident brief

The DRY\_RUN guard (default `true`) prevents live execution without explicit opt-in, making it safe to operate in a lab.

**Tier 3 — Enterprise Distributed SOAR Cluster**

The production-hardened upgrade to Tier 2, designed to handle real alert storms:

- **FastAPI Ingestion Gateway** — rate-limited at 500 req/min with a 3-stage cost-filter pyramid. A Sigma noise match, a Redis deduplication check (10-minute lookback via a single `EXISTS` call), and a brute-force attempt threshold gate eliminate the vast majority of alerts at pure CPU speed before any I/O or LLM call occurs.
- **RabbitMQ Event Bus** — durable queues ensure no alert is lost during worker restarts or brief outages.
- **Semantic Deduplication** — a `sentence-transformers/all-MiniLM-L6-v2` model encodes each alert into a 384-dimensional vector. Qdrant cosine similarity search (90% threshold, 10-minute lookback) bundles near-duplicate alerts into a single master incident, eliminating redundant LLM analysis of the same attack pattern.
- **4-Node LangGraph Pipeline:**
  - *Node 1 — Threat Intel Fan-out:* Six sources queried in parallel via `ThreadPoolExecutor` (AbuseIPDB, VirusTotal, OTX AlienVault, Shodan, MISP, and an internal blacklist). Total latency equals the slowest source, not their sum. Each source contributes to a composite 0–10 risk score; a missing API key degrades only that source without breaking the pipeline.
  - *Node 2 — MITRE ATT&CK Mapping:* Keyword scanning maps observables to specific ATT&CK technique IDs (e.g., T1110.001 for SSH brute force). Unmapped events default to T1078 (Valid Accounts).
  - *Adaptive Risk Router:* Alerts scoring ≥7.5 are frozen for human review; alerts below threshold proceed to auto-containment. The threshold itself is dynamic — every analyst denial shifts it upward via a Redis write, with no worker restart required.
  - *Node 3 — Active Containment:* Executes `iptables DROP` on validated IPs (RFC 1918 addresses are rejected). The DRY\_RUN guard remains in effect unless explicitly disabled in `.env`.
  - *Node 4 — Merkle-Chained Audit Ledger:* Every audit record is SHA-256 hashed with the previous row's hash (`SHA256(seq | logged_at | incident_id | event_json | prev_hash)`), anchored at `SHA256("GENESIS")`. Any row tampering invalidates every downstream hash, detected by `audit_verify()`. PII scrubbing removes RFC 1918 addresses and email patterns before persistence.
- **PostgreSQL HITL Checkpointing** — when an alert crosses the risk threshold, the LangGraph state is frozen in PostgreSQL and an SSE event pushes a Human-in-the-Loop approval card to the operator dashboard in under 2 seconds. Analyst approval resumes the workflow; denial records a feedback event and raises the adaptive threshold.
- **Adaptive Sigma Rule Generation** — every 10 analyst denials of the same alert type triggers Claude Haiku to read the 10 most recent false-positive raw logs and generate a Sigma suppression YAML, written to `SIEM-Detection/sigma/candidates/` for review before CI deployment.
- **Full Observability** — every LangGraph node is wrapped in an OpenTelemetry span exported to Jaeger via OTLP gRPC. A `_NoopTracer` fallback keeps the pipeline running in CI without a full Docker stack. Prometheus metrics are exposed at `/metrics`: alert counts by severity, containment counts, HITL queue depth, and live adaptive threshold.
- **Real-Time Operator Dashboard** — a Next.js frontend displays live HITL approval cards, active incidents, and the current risk threshold. Approve or deny directly from the UI; the backend state machine responds within the same SSE connection.

**Stack:** Python · FastAPI · LangGraph · Anthropic Claude · RabbitMQ · Redis · Qdrant · PostgreSQL · sentence-transformers · Docker Compose · OpenTelemetry · Jaeger · Prometheus · Next.js · Wazuh · Elastic Stack · Splunk HEC

---

#### Sub-Component: [SIEM Detection Library](https://github.com/VincentSuen6/VincentSuen6/tree/main/agentic-SOC-operator/SIEM-Detection)

A production-ready detection rule library covering six attack categories, deployed to both Wazuh and Splunk. Rules are authored by the `siem_generator` node in the Vulnerability Intelligence Agent pipeline — each rule is auto-generated after a CVE is decomposed, mapped to MITRE ATT&CK techniques, and back-ported into both SIEM platforms for closed-loop detection coverage.

| Rule Set | MITRE Techniques Covered | Attack Category |
|----------|--------------------------|-----------------|
| FIM / Secrets Tampering | T1565.001, T1552.001, T1098.004, T1548.003 | Credential Access, Impact |
| SSH Brute Force | T1110.001, T1110.003, T1078 | Credential Access |
| Privilege Escalation | T1548.001, T1548.003, T1068, T1055, T1547.006 | Privilege Escalation |
| Lateral Movement | T1021.002, T1021.001, T1550.002, T1003.001 | Lateral Movement |
| Ransomware Behavioral | T1486, T1490, T1489, T1562.001, T1059.001 | Impact |
| Exploit Public-Facing | T1190, T1505.003, T1059, T1210 | Initial Access |

Wazuh rules are XML-format, deployable to `/var/ossec/rules/`. Splunk SPL queries are structured as Saved Searches firing into the SOAR-Sentinel webhook on trigger. The `threat_intel_correlation.spl` dashboard surfaces enriched Splunk HEC events from the Python orchestration layer alongside raw SIEM data.

**Architectural Note:** The Splunk integration uses direct Elasticsearch API polling (`elastic_puller.py`) rather than Kibana Action Connectors, bypassing Kibana's 60–80% RAM footprint in the data path. This mirrors the architecture used by Palo Alto Cortex XSOAR and Splunk SOAR (Phantom) in production — both poll the Elasticsearch REST API directly for the same fault-tolerance and resource efficiency reasons discovered here.

---

#### Sub-Component: [Sentinel SOAR — Vulnerability Intelligence Agent](https://github.com/VincentSuen6/VincentSuen6/tree/main/agentic-SOC-operator/SOAR-sentinel)

A CVE decomposition and OSINT automation engine that takes a CVE identifier as input and produces complete threat intelligence, MITRE ATT&CK mappings, and SIEM detection rules as output.

The core is a **6-node LangGraph pipeline:**

1. **CVE Node** — queries the NVD API via `nvdlib` to decompose the CVE into CVSS score, affected products, and CWE classifications
2. **OSINT Node** — Claude AI performs open-source intelligence analysis on the CVE, identifying public exploit code, affected vendor patches, and real-world exploitation evidence
3. **TAXII Node** — queries the MITRE ATT&CK TAXII 2.1 feed via `stix2` to pull structured threat intelligence for observed TTPs
4. **Validator Node** — cross-references data from all three upstream nodes, computes a composite confidence score, and flags discrepancies
5. **MITRE Mapper Node** — produces the definitive ATT&CK technique mapping with sub-technique resolution
6. **Malware Behavior Node** — queries the 10-year MITRE ATT&CK dataset to find historical malware families that exploited the same TTPs, providing adversary profile context
7. **SIEM Generator Node** — produces Wazuh XML rules and Splunk SPL queries specific to the CVE's detection signatures, written to `SIEM-Detection/`

The **Active Response Agent** integrates directly: enriched alerts are passed to Claude with full telemetry context (Wazuh EDR, Elastic SIEM, Docker metrics), MITRE mapping, and historical incidents. Claude generates CVE mappings, triage priority scores, and specific validated remediation commands. A validation gate checks every command against an approved allowlist and a dry-run simulation before execution — confidence must exceed 0.92 for destructive commands. Every recommendation and executed command is appended to an immutable GitHub signed-commit ledger.

**Stack:** Python · LangGraph · Anthropic Claude · nvdlib · stix2 · AbuseIPDB · VirusTotal · OTX AlienVault · MISP · Shodan · Splunk HEC · Wazuh · Elastic

---

### [AegisLoop — Continuous Purple Team Control Validator](https://github.com/VincentSuen6/VincentSuen6/tree/main/purple-teaming/aegis-loop)

A purple-team automation platform that continuously answers one question: *"When an attacker runs a known exploit technique, does our WAF actually block it?"*

#### What It Does

AegisLoop spins up a realistic, isolated attack lab — OWASP Juice Shop (an intentionally vulnerable web application) deployed behind a ModSecurity/NGINX WAF with CRS paranoia level 2 — fires 10 OWASP Top 10 exploit modules at it, cross-correlates the HTTP responses against live WAF audit logs, computes a CVSS-weighted residual risk score, and emits a GitHub-dark-themed HTML scorecard plus a MITRE ATT&CK Navigator layer JSON in under 60 seconds.

The key design constraint is the **enforcement boundary**: Juice Shop runs on an `internal` Docker network with no exposed ports. The scanner reaches it exclusively through the WAF on the `external` network. Any attack that returns a 200 from the application is a confirmed WAF gap — not a test artifact.

#### Purple Team Methodology

```
1. PLAN    → Map attacks to MITRE ATT&CK T-codes + OWASP 2021 categories
2. ATTACK  → Fire exploit payloads at the WAF-fronted target
3. MEASURE → Correlate HTTP response codes with WAF audit log verdicts
4. SCORE   → Compute CVSS-weighted residual risk score (0–10)
5. REPORT  → Emit HTML scorecard + ATT&CK Navigator layer
6. LOOP    → GitHub Actions runs weekly to track control drift over time
```

The **telemetry correlation** step is the critical differentiator: a 403 from the WAF (BLOCKED) vs. a 200 from the application (BYPASSED) represent entirely different security postures. The `correlate()` function in `pipeline/telemetry.py` re-reads the WAF audit log after the attack phase and overlays verdicts onto findings — handling cases where the HTTP status code seen by the scanner conflicts with the WAF's actual logged decision.

#### Attack Module Catalog

| # | Module | MITRE Technique | OWASP Category | Severity | CVSS |
|---|--------|----------------|----------------|----------|------|
| 1 | SQL Injection (tautology auth bypass) | T1190 | A03 Injection | CRITICAL | 9.8 |
| 2 | Reflected XSS | T1059.007 | A03 Injection | HIGH | 7.2 |
| 3 | Path Traversal / LFI | T1083 | A01 Broken Access Control | HIGH | 7.5 |
| 4 | IDOR / BOLA (unauthenticated object access) | T1078 | A01 Broken Access Control | HIGH | 8.1 |
| 5 | Unix Shell Command Injection | T1059.004 | A03 Injection | CRITICAL | 9.8 |
| 6 | SSRF (cloud metadata probe) | T1090.001 | A10 SSRF | HIGH | 8.8 |
| 7 | XXE (file read via DOCTYPE entity) | T1005 | A05 Security Misconfiguration | HIGH | 7.5 |
| 8 | Open Redirect (phishing vector) | T1598.003 | A01 Broken Access Control | MEDIUM | 6.1 |
| 9 | Credential Stuffing (burst login) | T1110.004 | A07 Auth Failures | HIGH | 7.5 |
| 10 | Missing Security Headers audit | T1562.001 | A05 Security Misconfiguration | MEDIUM | 5.3 |

#### Output Artifacts

**HTML Scorecard** — dark-themed GitHub-style table with technique IDs, OWASP categories, CVSS scores, BLOCKED/BYPASSED/PARTIAL/UNTESTED status badges, HTTP codes, latency, and proof-of-exploitation evidence. Summary badges show gap count, covered count, residual risk score (0–10), and trend delta (↑/↓ vs. last run).

**MITRE ATT&CK Navigator Layer** — v4.9-compatible JSON layer with technique cells color-coded by control status, score gradient (100 = gap confirmed, 0 = covered), and hover metadata including CVSS, HTTP status, latency, and evidence. Load directly into the bundled ATT&CK Navigator instance (`localhost:8082`).

**Raw JSON** — machine-readable output including the `risk_score` field. Pipe into SIEM/SOAR or diff two runs programmatically to measure control improvement over time.

**Residual Risk Score** — computed as `Σ(CVSS for each BYPASSED/UNTESTED finding) / total_modules`. Rewards coverage breadth (larger denominator) and weights high-CVSS gaps more heavily (larger numerator). Interpreted as: 0.0–3.9 (Low), 4.0–6.9 (Medium), 7.0–10.0 (High).

#### CI/CD Pipeline

A GitHub Actions workflow runs weekly (Mondays 03:00 UTC) and on manual trigger with an optional `target_url` override. The pipeline: checks out → spins up the Docker lab → health-checks all three services → runs the full assessment → uploads `reports/` and `navigator-data/` as 90-day artifacts → tears down.

**Stack:** Python · FastAPI · ModSecurity/NGINX · OWASP Juice Shop · Pydantic · Jinja2 · Rich · Typer · Docker Compose · MITRE ATT&CK Navigator · GitHub Actions

---

### [C2 Framework — Red Team Command and Control](https://github.com/VincentSuen6/VincentSuen6/tree/main/red-teaming/C2)

>  **Authorized use only.** Built for controlled lab environments, authorized penetration testing engagements, and red team research. Never deploy against systems without explicit written permission.

A modular Command and Control (C2) framework for authorized red team operations, built to emulate the operational patterns of commodity post-exploitation frameworks at the component level. The goal is to understand how real adversaries establish persistence and execute TTPs — knowledge that directly informs the detection engineering work in the SOAR platform.

#### Architecture

The framework is organized into five components, each running as a separate Python module:

**Server (`server/`)** — a FastAPI application backed by SQLite. Manages beacon registration, task queuing, and result collection. Key endpoints:
- `POST /beacon/register` — registers a new implant, returns a UUID beacon ID
- `GET /beacon/{beacon_id}/tasks` — atomic task dispatch: fetches pending tasks, marks them `dispatched` in a single transaction, and updates `last_seen`
- `POST /results` — receives task results and telemetry from the beacon

**Beacon (`beacon/`)** — the implant that runs on the target host. On startup it registers with the C2 server, then enters a jittered polling loop (configurable base sleep + random jitter) to pull tasks and report results. Task execution is dispatched to TTP modules via the `dispatcher` interface. Fully configurable via environment variables (`C2_URL`, `C2_SLEEP`, `C2_JITTER`).

**Operator (`operator/`)** — a CLI (`cli.py`) used by the red team operator to interact with registered beacons: list active beacons, queue tasks, and review results.

**Bridge (`bridge/`)** — a Frida-based dynamic instrumentation layer. Frida hooks (`frida_hooks/`) allow runtime interception of target process calls, enabling in-memory analysis and behavioral telemetry collection without static modification of binaries.

**TTPs (`ttps/`)** — TTP modules that the beacon's dispatcher executes on task. Current module:
- `process_injection.py` — implements process injection techniques for executing code within the address space of a running process, emulating T1055 (Process Injection) from MITRE ATT&CK

#### Design Philosophy

Each component is deliberately minimal — the server is a few hundred lines of FastAPI, the beacon is a polling loop with a dispatcher interface. The intent is to understand the fundamental mechanics of C2 communication (beacon registration, jittered heartbeat, task dispatch, result collection) and post-exploitation TTP execution at the source level, not to wrap a GUI around an existing framework. This ground-up construction directly informs the detection signatures in the SIEM Detection Library and the active response logic in the SOAR platform.

**Stack:** Python · FastAPI · SQLite · Frida · MITRE ATT&CK T1055

---

##  Education & Institutional Leadership

-  **B.A.Sc. in Computer Science** | Simon Fraser University
-  **External Director** | Simon Fraser University Cybersecurity Club
-  **Research Assistant** | SFU Department of Cybersecurity and AI

##  Connect with Me

- 💼 **LinkedIn:** [linkedin.com/in/vsuen6](https://linkedin.com/in/vsuen6)
- 🐙 **GitHub:** [github.com/VincentSuen6](https://github.com/VincentSuen6)
- 📧 **Email:** [vincentsuen6@gmail.com](mailto:vincentsuen6@gmail.com)

*"Protecting enterprise systems through data-driven security analysis."*
