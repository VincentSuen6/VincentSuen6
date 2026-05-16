# Sentinel SOAR — Autonomous Multi-SIEM Intelligence Pipeline

**Wazuh + Elastic + Splunk + Claude AI — closed-loop threat detection and remediation**

```
┌─────────────────────────────────┐     ┌──────────────────────────────────────┐
│       THREAT INTEL FEEDS        │     │          SECURITY TELEMETRY          │
│                                 │     │                                      │
│  AbuseIPDB   TAXII/STIX         │     │  Wazuh EDR        Elastic SIEM       │
│  VirusTotal  OTX AlienVault     │     │  Host/FIM/Rootkit Network/Sysmon     │
│  MISP        Shodan             │     │                                      │
└────────────┬────────────────────┘     │  Docker Containers                   │
             │                         │  Containerized Logs                  │
             ▼                         └──────────────┬───────────────────────┘
   ┌──────────────────────┐                           │
   │  Data Enrichment     │◄──────────────────────────┘
   │  Engine              │
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │  Splunk SIEM — HEC   │
   │  Forensics/Dashboards│
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │  Claude AI Analyst   │
   │  CVE Mapping +       │
   │  Strategy Gen        │
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐        ┌──────────────────────────┐
   │  Active Response     │───────►│  GitHub Audit Ledger     │
   │  Closed-Loop         │        │  Immutable Forensic      │
   │  Remediation         │        │  Record                  │
   └──────────┬───────────┘        └──────────────────────────┘
              │
              ▼  iptables / chmod / kill
          Endpoint
```

---

## Executive Summary

A Security Orchestration, Automation and Response (SOAR) pipeline integrating Wazuh EDR, Elastic SIEM, and Splunk HEC with enrichment from six external threat intel sources. Claude AI maps alerts to CVEs, generates remediation strategies, and an Active Response Agent executes validated commands — maintaining a cryptographically immutable forensic audit trail throughout.

---

## Telemetry Collection

Three complementary collection layers feed the pipeline:

| Source | Detection Scope |
|--------|----------------|
| **Wazuh EDR** | Host-based — file integrity monitoring, rootkit detection, registry changes, process injection |
| **Elastic SIEM** | Network-level — Sysmon events, east-west traffic, lateral movement detection |
| **Docker Containers** | Containerized service telemetry — escape detection, anomalous process spawns |

---

## Threat Intelligence Enrichment

Every alert and observable is enriched against six external sources before analysis:

| Source | Enrichment Type |
|--------|----------------|
| **AbuseIPDB** | IP reputation scoring and abuse confidence rating |
| **TAXII / STIX** | Structured threat intel feeds — ATT&CK, ISACs, government feeds |
| **VirusTotal** | File hash and URL reputation across 70+ AV engines |
| **OTX AlienVault** | Open Threat Exchange — IOC correlation and pulse matching |
| **MISP** | Malware information sharing platform — community threat data |
| **Shodan** | Asset exposure context for IPs observed in alerts |

---

## Claude AI Analyst

Enriched alerts are passed to Claude with full context — telemetry, enrichment data, MITRE ATT&CK mapping, and historical incidents. Claude generates:

- **CVE mapping** — links observable TTPs to known vulnerabilities
- **Remediation strategy** — specific validated commands (`iptables`, `chmod`, `kill`) with reasoning
- **Triage priority** — risk score considering asset criticality and threat actor profile

> **Design constraint:** Claude recommends, pipeline validates, agent executes. No command runs without a validation gate — prevents destructive actions under adversarial conditions.

---

## Forensic Audit Trail

Every LLM recommendation and executed command is appended to an immutable GitHub ledger — signed commits provide a tamper-evident forensic record of every autonomous decision.

---

## Approach

**01 — EDR & SIEM Deployment**
Deploy Wazuh agents and Elastic SIEM across endpoints for host and network telemetry collection.

**02 — Threat Intel Integration**
Connect AbuseIPDB, TAXII, VirusTotal, OTX, MISP, and Shodan APIs to the enrichment engine.

**03 — Python Orchestration Layer**
Build middleware to ingest telemetry, enrich observables, route events to Splunk HEC by severity.

**04 — Claude AI Integration**
Wire enriched alert context to Claude API for CVE mapping, remediation generation, and triage scoring.

**05 — Active Response + Audit**
Deploy response agent with validation gate, append every action to immutable GitHub forensic ledger.

---

## Components

| Component | Layer | Responsibility |
|-----------|-------|---------------|
| Wazuh EDR | Telemetry | Host-based detection — FIM, rootkit, registry, process injection |
| Elastic SIEM | Telemetry | Network-level detection — Sysmon, east-west traffic, lateral movement |
| Python Orchestrator | Processing | Ingests telemetry, coordinates enrichment, routes to Splunk HEC by severity |
| Enrichment Engine | Intel | Queries AbuseIPDB, VirusTotal, OTX, MISP, TAXII, Shodan per observable |
| Splunk HEC | Analytics | Forensic dashboards, detection rule evaluation, MITRE ATT&CK correlation |
| Claude AI Analyst | Reasoning | CVE mapping, remediation strategy gen, triage priority scoring |
| Response Agent | Execution | Validated closed-loop remediation — `iptables`, `chmod`, process kill |
| GitHub Audit Ledger | Compliance | Signed, immutable forensic record of every AI decision and executed command |

---

## Engineering Challenges

**Problem:** Wazuh and Elastic produce different alert schemas — merging them into a single normalized event for enrichment without losing source-specific context fields.

**Fix:** Built a schema normalization layer in the Python Orchestrator that maps both alert formats to a canonical internal schema, preserving raw source fields in a passthrough object for Splunk.

---

**Problem:** Alert fatigue — Claude was receiving hundreds of low-severity events per minute and generating remediation strategies for each, creating noise and burning API quota.

**Fix:** Added a severity gating layer — only alerts scoring 7.0+ CVSS after enrichment are forwarded to Claude. Lower severity events are batched into a daily digest for trend analysis.

---

**Problem:** The Active Response Agent could issue destructive commands (`iptables DROP`, `kill -9`) based on a mis-classified alert — no human review in a fully autonomous loop.

**Fix:** Introduced a validation gate — every command Claude recommends is checked against an allowlist of approved actions and a dry-run simulation before execution. Destructive commands require a confidence score above 0.92.

---

## Project Structure

```
SOAR-sentinel/
├── vuln-intel-agent/
│   ├── detection/
│   │   ├── pipeline_bridge.py       ← Wazuh → GitHub pusher
│   │   └── log_orchestrator.py      ← multi-source telemetry hub
│   ├── intelligence/
│   │   ├── enrichment_engine.py     ← AbuseIPDB/VT/OTX/Shodan/MISP
│   │   ├── splunk_hec.py            ← Splunk HEC client
│   │   └── live_threats.json        ← active threat record
│   ├── nodes/
│   │   ├── cve_node.py              ← NVD API decomposition
│   │   ├── osint_node.py            ← Claude OSINT analysis
│   │   ├── taxii_node.py            ← MITRE TAXII/STIX feed
│   │   ├── validator_node.py        ← cross-source confidence scoring
│   │   ├── mitre_mapper.py          ← ATT&CK technique mapping
│   │   ├── malware_behavior_node.py ← 10-year malware analysis
│   │   └── siem_generator.py        ← Wazuh + Splunk rule generation
│   ├── response/
│   │   └── active_response_agent.py ← Claude analyst + executor
│   ├── graph.py                     ← LangGraph orchestrator
│   ├── main.py                      ← CLI entry point
│   └── state.py                     ← shared AgentState TypedDict
└── README.md
```

---

## Tech Stack

Wazuh · Elastic · Splunk · Docker · Python · Anthropic API · AbuseIPDB · TAXII/STIX · VirusTotal · MISP · LangGraph · nvdlib · stix2

---

## Quick Start

```bash
cd vuln-intel-agent
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env    # fill in API keys

# Run full CVE intelligence pipeline
python main.py CVE-2024-3400

# Run Active Response Agent (one-shot on local threat)
python response/active_response_agent.py --local

# Run log orchestrator (all three telemetry sources)
python detection/log_orchestrator.py
```

See [vuln-intel-agent/README.md](vuln-intel-agent/README.md) for full setup and VMware hosting instructions.
