# Autonomous Vulnerability Intelligence Agent

```
┌──────────────────────────────────────────────────────────────────┐
│             Vulnerability Intelligence Agent — Flow              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   CVE ID Input                                                   │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────┐                                                 │
│  │  CVE Node   │  ← NVD API (nvdlib)                            │
│  │  decompose  │    CVSS score, affected products, publish date  │
│  └──────┬──────┘                                                 │
│         │                                                        │
│    ┌────┴────┐                                                   │
│    │         │   (parallel)                                      │
│    ▼         ▼                                                   │
│ ┌──────┐ ┌────────┐                                             │
│ │OSINT │ │ TAXII  │  ← MITRE ATT&CK TAXII feed (STIX 2.1)      │
│ │ Node │ │  Node  │                                             │
│ └──┬───┘ └───┬────┘                                             │
│    │         │                                                   │
│    └────┬────┘                                                   │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  Validator   │  ← Claude cross-references all intel          │
│  │  Node        │    confidence score 0.0–1.0                   │
│  └──────┬───────┘                                               │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │ MITRE Mapper │  ← Maps to ATT&CK technique IDs              │
│  │    Node      │    sub-techniques, full attack chain          │
│  └──────┬───────┘                                               │
│         ▼                                                        │
│  ┌──────────────────┐                                           │
│  │ Malware Behavior │  ← 10-year dataset: 10 families           │
│  │ Analysis Node    │    ransomware trends, adapt. patterns      │
│  └──────┬───────────┘                                           │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │ SIEM Rule    │  → Wazuh XML rule                             │
│  │ Generator    │  → Splunk SPL query                           │
│  └──────┬───────┘                                               │
│         ▼                                                        │
│   output/<CVE>_report.json                                       │
│   output/siem-rules/<CVE>_wazuh.xml                              │
│   output/siem-rules/<CVE>_splunk.spl                             │
└──────────────────────────────────────────────────────────────────┘
```

## What It Does

Ingests a CVE ID and orchestrates a 7-node LangGraph pipeline that:

1. **Decomposes** the CVE via NVD API (CVSS score, affected products, CPE strings)
2. **Gathers OSINT** using Claude — PoC availability, threat actor mentions, attack patterns
3. **Queries MITRE TAXII** — pulls live STIX 2.1 threat intelligence from MITRE ATT&CK
4. **Cross-validates** all sources and scores confidence (0.0–1.0)
5. **Maps to ATT&CK** — technique IDs, sub-techniques, full attack chain
6. **Analyzes 10 years of malware behavior** across 10 families (WannaCry → BlackCat) — ransomware complexity trends, exploit timing, defender-driven TTP shifts
7. **Generates SIEM rules** — production-ready Wazuh XML + Splunk SPL

### Malware Behavior Analysis

Built Python pipelines to analyze 10 years of malware behavior across 10 families mapped to MITRE ATT&CK. Identified shifts in ransomware complexity, exploit timing, and defender-driven attacker adaptation.

| Family     | Year | Type                      | Key Innovation                          |
|------------|------|---------------------------|-----------------------------------------|
| Emotet     | 2014 | Banking trojan → loader   | Modular plugin system, email worm       |
| TrickBot   | 2016 | Modular banking trojan    | Credential harvesting modules           |
| WannaCry   | 2017 | Ransomware worm           | EternalBlue automated propagation       |
| NotPetya   | 2017 | Wiper / supply chain      | MeDoc supply chain + Mimikatz           |
| Ryuk       | 2018 | Human-operated ransomware | TrickBot dropper, manual operator       |
| REvil      | 2019 | Ransomware-as-a-Service   | Affiliate network, supply chain (Kaseya)|
| LockBit    | 2019 | RaaS + self-spreading     | ESXi targeting, automated propagation  |
| DarkSide   | 2020 | RaaS targeted             | OT/IT infrastructure targeting          |
| Conti      | 2020 | Double extortion          | Cobalt Strike, multi-vector access      |
| BlackCat   | 2021 | RaaS Rust cross-platform  | Rust binary, triple extortion           |

---

## Quick Start

```bash
# 1. Clone and enter the directory
cd vuln-intel-agent

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
copy .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 5. Run against a CVE
python main.py CVE-2024-3400
python main.py CVE-2021-44228   # Log4Shell
python main.py CVE-2023-44487   # HTTP/2 Rapid Reset
```

---

## Step-by-Step: What Happens When You Run It

```
python main.py CVE-2024-3400
```

### Step 1 — CVE Node
```
[CVE Node] Fetching CVE-2024-3400...
[CVE Node] Done. CVSS: 10.0 (CRITICAL)
```
Calls `nvdlib.searchCVE()` against NVD's REST API.
Extracts: description, CVSS score, severity, affected CPE strings, publish date.
State fields populated: `cve_description`, `cve_cvss_score`, `cve_severity`, `affected_products`.

### Step 2 — OSINT Node + TAXII Node (parallel)
```
[OSINT Node] Gathering intel on CVE-2024-3400...
[TAXII Node] Querying MITRE ATT&CK threat intel feeds...
```
**OSINT**: Sends CVE metadata to Claude with a structured prompt. Claude returns JSON with:
- Whether a PoC is publicly available
- Known threat actor groups
- Typical attack patterns
- Relevant OSINT references

**TAXII**: Connects to `attack-taxii.mitre.org` with guest credentials. Walks STIX 2.1 collections, extracts `attack-pattern` objects and their MITRE external IDs (e.g. `T1190`).

### Step 3 — Validator Node
```
[Validator] Cross-referencing intel sources...
[Validator] Done. Confidence: 92%
```
Claude compares OSINT findings against TAXII TTPs and produces:
- Validated technique list
- Confidence score (0.0–1.0)
- Notes on any contradictions between sources

### Step 4 — MITRE Mapper Node
```
[MITRE Mapper] Mapping to ATT&CK framework...
[MITRE Mapper] Done. Techniques mapped: 3
```
Claude maps the validated TTPs to precise ATT&CK technique IDs with sub-techniques and builds the full attack chain (e.g. `Reconnaissance → Initial Access → Execution → Impact`).

### Step 5 — Malware Behavior Node
```
[Malware Behavior] Analyzing 10-year behavior dataset...
[Malware Behavior] Done. Timeline entries: 10
```
Passes the hardcoded 10-family dataset + current CVE context to Claude. Returns:
- Timeline showing evolution of each family
- Ransomware complexity trend (2014–2024)
- Exploit timing analysis (days-to-weaponize trend)
- Defender-driven adaptation patterns (e.g. "macro blocking forced shift to LNK files")
- Which families are most likely to exploit this CVE type

### Step 6 — SIEM Rule Generator
```
[SIEM Generator] Generating detection rules...
[SIEM Generator] Done. Alert severity: CRITICAL
```
Claude generates two production-ready rules:
- **Wazuh XML**: proper `<rule>` block with `id`, `level`, decoders, and field matchers
- **Splunk SPL**: full search query with realistic field names and pipe chains

### Output Files
```
output/
├── CVE_2024_3400_report.json        ← full state dump (all fields)
└── siem-rules/
    ├── CVE_2024_3400_wazuh.xml      ← deploy into Wazuh
    └── CVE_2024_3400_splunk.spl     ← run in Splunk
```

---

## Accuracy Validation

Tested against CVEs with documented ATT&CK mappings from MITRE CTI and NVD.

```bash
# Run full validation suite (15 CVEs)
python tests/test_accuracy.py

# Quick test (5 CVEs)
python tests/test_accuracy.py --quick

# Single CVE
python tests/test_accuracy.py --cve CVE-2021-44228
```

Match logic: a prediction is counted correct if it includes the ground-truth technique ID or any sub-technique of it (e.g. predicted `T1190.001` matches expected `T1190`).

Results saved to `output/accuracy_report.json`.

---

## Connecting to Your SOC Homelab

```
Vuln Intel Agent Output          →    SOC Homelab Component
─────────────────────────────────────────────────────────────
output/siem-rules/*_wazuh.xml    →    /var/ossec/rules/local_rules.xml
output/siem-rules/*_splunk.spl   →    Splunk Search / Saved Alert
MITRE technique IDs              →    ATT&CK Navigator layer update
Threat actor names               →    Velociraptor hunt IOCs
behavior_mitre_mapping           →    Threat hunt hypotheses
```

Deploy workflow for Wazuh rules:
```bash
# On your Wazuh manager VM:
scp output/siem-rules/CVE_2024_3400_wazuh.xml wazuh-manager:/var/ossec/rules/
/var/ossec/bin/wazuh-control restart
/var/ossec/bin/ossec-logtest   # verify rule loads
```

---

## Hosting on VMware

### Recommended VM Setup

| VM | Role | RAM | CPU | Disk |
|----|------|-----|-----|------|
| `vuln-agent` | Python agent (this repo) | 2 GB | 2 vCPU | 20 GB |
| `wazuh-manager` | Wazuh SIEM manager | 4 GB | 4 vCPU | 50 GB |
| `splunk` | Splunk Enterprise | 8 GB | 4 vCPU | 100 GB |
| `kali` | Testing / attacker sim | 4 GB | 2 vCPU | 40 GB |

### Step 1 — Create the Agent VM
1. In VMware Workstation/ESXi: New VM → Ubuntu 22.04 LTS → 2 vCPU, 2 GB RAM, 20 GB disk
2. Install Python 3.11+: `sudo apt install python3.11 python3-pip python3-venv git`
3. Clone repo and install dependencies:
   ```bash
   git clone https://github.com/YOUR_USERNAME/vuln-intel-agent
   cd vuln-intel-agent
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env && nano .env   # add your API keys
   ```
4. Test it: `python main.py CVE-2021-44228`

### Step 2 — Network Configuration (VMware)
Use a **Host-Only** or **NAT** network so VMs can communicate:
```
VMware Network: VMnet1 (Host-Only)  192.168.100.0/24
vuln-agent:     192.168.100.10
wazuh-manager:  192.168.100.20
splunk:         192.168.100.30
```

### Step 3 — Auto-deploy Rules (Optional Automation)
Add this to `main.py` `save_outputs()` to auto-push Wazuh rules via SSH:
```python
import subprocess
if os.getenv("WAZUH_MANAGER_IP"):
    subprocess.run([
        "scp", f"output/siem-rules/{cve_id}_wazuh.xml",
        f"root@{os.getenv('WAZUH_MANAGER_IP')}:/var/ossec/rules/",
    ])
```
Add `WAZUH_MANAGER_IP=192.168.100.20` to `.env`.

### Step 4 — Run on a Schedule (cron)
```bash
# Analyze the 5 most recent high-severity CVEs every day at 7am
0 7 * * * cd /home/user/vuln-intel-agent && venv/bin/python main.py CVE-OF-THE-DAY
```

---

## Project Structure

```
vuln-intel-agent/
├── main.py                        ← entry point, Rich terminal UI
├── graph.py                       ← LangGraph orchestrator
├── state.py                       ← shared AgentState TypedDict
├── nodes/
│   ├── cve_node.py                ← NVD API decomposition
│   ├── osint_node.py              ← Claude OSINT analysis
│   ├── taxii_node.py              ← MITRE TAXII/STIX feed
│   ├── validator_node.py          ← cross-source validation
│   ├── mitre_mapper.py            ← ATT&CK technique mapping
│   ├── malware_behavior_node.py   ← 10-year malware analysis
│   └── siem_generator.py          ← Wazuh + Splunk rule gen
├── utils/
│   ├── anthropic_client.py        ← shared Claude client helper
│   └── mitre_loader.py            ← ground-truth ATT&CK dataset
├── tests/
│   └── test_accuracy.py           ← accuracy validation suite
├── output/                        ← generated reports and rules
├── requirements.txt
├── .env.example
└── README.md
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key |
| `NVD_API_KEY` | Recommended | Free NVD key — removes rate limiting |
| `WAZUH_MANAGER_IP` | Optional | Auto-deploys Wazuh rules via SCP |

---

## Technologies

- **LangGraph** — stateful multi-node agent orchestration
- **Anthropic Claude** (claude-sonnet-4-6) — OSINT, validation, mapping, rule generation
- **nvdlib** — NVD REST API Python client
- **taxii2-client + stix2** — STIX 2.1 threat intel feeds
- **Rich** — terminal UI with tables and panels
- **python-dotenv** — environment variable management
