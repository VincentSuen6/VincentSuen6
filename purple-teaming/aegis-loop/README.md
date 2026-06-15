# AegisLoop

**Continuous purple-team control validation — adversarial attacks, automated WAF scoring, and MITRE ATT&CK reporting in a single pipeline.**

> ⚠️ **Authorized use only.** AegisLoop is purpose-built for controlled lab environments. All traffic targets OWASP Juice Shop, an intentionally vulnerable application. Never run against systems you do not own or have explicit written permission to test.

---

## What It Does

AegisLoop answers one question continuously:

> *"When an attacker runs a known exploit technique, does our WAF actually block it?"*

It spins up a realistic attack lab (Juice Shop behind ModSecurity/NGINX), fires 10 OWASP Top 10 exploit modules, cross-correlates the results against live WAF audit logs, computes a CVSS-weighted residual risk score, and emits a GitHub-dark-themed HTML scorecard plus a MITRE ATT&CK Navigator layer — all in under 60 seconds.

Each run saves a `raw_*.json` file so the next run can show a trend delta (↑ / ↓ gaps vs last run).

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     Docker Compose Lab                       │
  │                                                              │
  │   ┌────────────────────┐      internal-net only              │
  │   │  OWASP Juice Shop  │◄──────────────────────────────────┐ │
  │   │  (port 3000)       │                                   │ │
  │   └────────────────────┘                                   │ │
  │            ▲                                               │ │
  │            │  proxied via internal network                 │ │
  │   ┌────────┴───────────┐      external-net                 │ │
  │   │  ModSecurity/NGINX │◄──── AegisLoop Scanner ──────────┘ │
  │   │  WAF (port 8080)   │      (Python, host)                │ │
  │   └────────────────────┘                                     │
  │                                                              │
  │   ┌────────────────────┐                                     │
  │   │  ATT&CK Navigator  │  reads navigator-data/             │
  │   │  (port 8082)       │  purple_matrix.json                │
  │   └────────────────────┘                                     │
  └──────────────────────────────────────────────────────────────┘

  Scanner output:
    reports/report_<id>.html     ← HTML scorecard
    reports/raw_<id>.json        ← machine-readable results
    navigator-data/purple_matrix.json  ← ATT&CK Navigator layer
    waf-logs/access.log          ← WAF audit log (correlated)
```

**Enforcement boundary:** Juice Shop is on an `internal` Docker network with no exposed ports. The scanner can only reach it through the WAF on the `external` network. This means every attack that bypasses the WAF is a real gap, not a test artefact.

---

## Purple Team Methodology

```
  1. PLAN      Map attacks to MITRE ATT&CK techniques + OWASP categories
  2. ATTACK    Fire exploit payloads at the WAF-fronted target
  3. MEASURE   Correlate HTTP response codes with WAF audit log verdicts
  4. SCORE     Compute CVSS-weighted residual risk score
  5. REPORT    Emit HTML scorecard + ATT&CK Navigator layer
  6. LOOP      Schedule weekly CI runs to track control drift over time
```

The key insight is **telemetry correlation**: a 403 from the WAF (BLOCKED) vs a 200 from the app (BYPASSED) tells you whether the WAF or the app handled the attack — two very different security postures.

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Python 3.11+
- Make

### 1. Start the Lab

```bash
make up
```

This starts Juice Shop, the ModSecurity WAF, and the ATT&CK Navigator. Health checks wait until all three are ready (typically 30–60 seconds on first pull).

### 2. Install Scanner

```bash
make install
```

Creates a `venv/` and installs all Python dependencies.

### 3. Run Assessment

```bash
make assess
```

Fires all 10 attack modules, correlates WAF logs, and writes reports to `./reports/` and `./navigator-data/`.

### 4. View Reports

- **HTML Scorecard**: open `reports/report_<id>.html` in a browser
- **ATT&CK Navigator**: go to `http://localhost:8082`, choose *Open Existing Layer → Upload File*, upload `navigator-data/purple_matrix.json`
- **WAF Logs**: `make logs` (streams live)

### 5. Tear Down

```bash
make down
```

---

## Module Catalog

| # | Module | Technique ID | OWASP Category | Severity | CVSS |
|---|--------|-------------|----------------|----------|------|
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

---

## Configuration

All settings are controlled via environment variables (or a `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_TARGET_URL` | `http://localhost:8080` | WAF URL (not the app directly) |
| `AEGIS_REQUEST_TIMEOUT` | `10` | HTTP timeout per request (seconds) |
| `AEGIS_RATE_LIMIT_DELAY` | `0.5` | Delay between module submissions (seconds) |
| `AEGIS_MAX_WORKERS` | `5` | ThreadPoolExecutor concurrency |
| `AEGIS_ASSESSOR` | `Purple Team` | Name written to reports |
| `AEGIS_REPORT_DIR` | `./reports` | Output directory for HTML + raw JSON |
| `AEGIS_NAVIGATOR_DIR` | `./navigator-data` | Output directory for ATT&CK layer |
| `AEGIS_WAF_LOG_PATH` | `./waf-logs/access.log` | WAF audit log path for correlation |

**Example `.env`:**

```dotenv
AEGIS_TARGET_URL=http://localhost:8080
AEGIS_MAX_WORKERS=3
AEGIS_RATE_LIMIT_DELAY=1.0
```

---

## CLI Reference

```
# Full assessment (attack + correlate + report)
aegisloop run

# Override target URL for this run only
aegisloop run --target http://staging.internal:8080

# Skip WAF log correlation (useful when log path is unavailable)
aegisloop run --no-waf

# Regenerate reports from a saved raw results file
aegisloop report reports/raw_abc12345.json
```

---

## Report Outputs

### HTML Scorecard (`reports/report_<id>.html`)

Dark-themed GitHub-style table showing every finding:

- **Technique ID + Name** — links conceptually to MITRE ATT&CK
- **OWASP Category** — maps to the 2021 Top 10
- **Severity + CVSS** — color-coded (red/orange/yellow/green)
- **Status badge** — BLOCKED (green) / BYPASSED (red) / PARTIAL (yellow) / UNTESTED (grey)
- **HTTP code + latency** — raw response metadata
- **Evidence** — extracted proof-of-exploitation where present

**Summary badges:**
- Total techniques tested
- Gap count (BYPASSED + UNTESTED)
- Covered count (BLOCKED)
- **Residual Risk Score** — CVSS-weighted score `0–10` (sum of bypassed CVSS / total modules)
- **Trend** — `↑ +2 vs last run` or `↓ -1 vs last run`

### ATT&CK Navigator Layer (`navigator-data/purple_matrix.json`)

ATT&CK Navigator v4.9 compatible layer:

- Technique cells colored by control status
- Score gradient: 100 = gap confirmed, 0 = covered
- Hover metadata: OWASP category, severity, CVSS, HTTP status, latency, evidence
- Legend explaining all 4 status categories

### Raw JSON (`reports/raw_<id>.json`)

Machine-readable full output, including the `risk_score` field. Feed this into SIEM/SOAR or diff two runs programmatically:

```python
import json
a = json.loads(open("reports/raw_abc.json").read())
b = json.loads(open("reports/raw_def.json").read())
print("Δ gaps:", len([f for f in b["findings"] if f["control_status"] == "BYPASSED"])
               - len([f for f in a["findings"] if f["control_status"] == "BYPASSED"]))
```

---

## Residual Risk Score

The **residual risk score** is computed as:

```
risk_score = Σ(cvss_score for each BYPASSED/UNTESTED finding) / total_modules
```

This gives a 0–10 score that:
- Rewards having more modules (denominator grows)
- Weights high-CVSS gaps more heavily (numerator grows by CVSS value)
- Reaches 10 only if every module is bypassed with maximum CVSS

**Interpretation:**
- `0.0 – 3.9` — Low residual risk (most controls effective)
- `4.0 – 6.9` — Medium residual risk (some gaps present)
- `7.0 – 10.0` — High residual risk (critical gaps confirmed)

---

## WAF Telemetry Correlation

After the attack phase, `correlate()` in `pipeline/telemetry.py` re-reads the WAF audit log and overlays verdicts onto findings. This handles the case where the HTTP status code seen by the scanner (e.g., a 200 from the app) conflicts with the WAF's actual decision (which may have logged a block before rewriting to allow).

Correlation uses two log formats:
1. **ModSecurity JSON audit log** — parses `transaction.response.http_code`
2. **Nginx combined log** — regex extracts status code from the standard access log format

Fingerprint patterns map log entries back to technique IDs using the attack signatures (SQLi patterns, `<script>` tags, `../` traversal sequences, etc.).

---

## Docker Services

| Service | Image | Internal Port | Exposed |
|---------|-------|---------------|---------|
| `juice-shop` | `bkimminich/juice-shop` | 3000 | No (internal only) |
| `modsecurity-waf` | `owasp/modsecurity-crs:nginx` | 80 | `8080:80` |
| `attack-navigator` | `ghcr.io/mitre-attack/attack-navigator` | 4200 | `8082:4200` |

**Resource limits:** WAF is capped at 0.5 CPU / 256 MB; Juice Shop at 1 CPU / 512 MB.

**WAF configuration:** ModSecurity CoreRuleSet at paranoia level 2, anomaly scoring threshold 5 (request) / 4 (response). JSON audit logging enabled.

---

## CI/CD Pipeline (`.github/workflows/assessment.yml`)

The GitHub Actions workflow runs weekly (Mondays 03:00 UTC) and on manual trigger:

```
1. Checkout
2. docker compose up -d   ← spin up lab
3. Health-check loop      ← wait for all services
4. make install           ← create venv
5. make assess            ← run full assessment
6. Upload artifacts       ← reports/ and navigator-data/ retained 90 days
7. docker compose down    ← cleanup
```

Manual trigger accepts an optional `target_url` input to override the default.

---

## Extending AegisLoop

### Add a New Attack Module

1. Create `src/aegisloop/modules/my_attack.py`:

```python
from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

class MyAttackModule(BaseModule):
    technique_id = "T1234"
    technique_name = "My Attack Technique"
    owasp_category = "A03:2021-Injection"
    severity = Severity.HIGH
    cvss_score = 7.5

    def execute(self) -> FindingResult:
        resp, elapsed, error = self._request("GET", "/my/endpoint?param=payload")
        result = self._build_result("my_payload", "/my/endpoint", resp, elapsed, error)
        if resp and resp.status_code == 200:
            result.evidence = "Payload reached application."
        return result
```

2. Register it in `src/aegisloop/modules/__init__.py`:

```python
from .my_attack import MyAttackModule
ALL_MODULES = [..., MyAttackModule]
```

3. Add a WAF fingerprint in `src/aegisloop/pipeline/telemetry.py`:

```python
_FINGERPRINTS["my_payload_pattern"] = "T1234"
```

4. Add payload variants to `config/payloads.yaml`.

### Custom Registration (Runtime)

```python
runner = AssessmentRunner(config)
runner.register(MyAttackModule)
findings = runner.run()
```

---

## Project Structure

```
aegis-loop/
├── src/aegisloop/
│   ├── cli.py                      # Entry point (typer app)
│   ├── core/
│   │   ├── models.py               # Pydantic data models
│   │   ├── base_module.py          # Abstract base class for modules
│   │   └── session.py              # HTTP session with retry/pooling
│   ├── modules/
│   │   ├── injection.py            # T1190  SQLi
│   │   ├── xss.py                  # T1059.007  Reflected XSS
│   │   ├── broken_auth.py          # T1083  Path Traversal
│   │   ├── idor.py                 # T1078  IDOR/BOLA
│   │   ├── cmdi.py                 # T1059.004  Command Injection
│   │   ├── ssrf.py                 # T1090.001  SSRF
│   │   ├── xxe.py                  # T1005  XXE
│   │   ├── open_redirect.py        # T1598.003  Open Redirect
│   │   ├── credential_stuffing.py  # T1110.004  Credential Stuffing
│   │   └── sec_headers.py          # T1562.001  Security Headers
│   ├── pipeline/
│   │   ├── runner.py               # Orchestration, concurrent exec, risk score
│   │   └── telemetry.py            # WAF log correlation
│   └── reporting/
│       ├── html_report.py          # Jinja2 HTML scorecard
│       └── navigator.py            # ATT&CK Navigator JSON layer
├── config/
│   └── payloads.yaml               # Payload variant catalog per technique
├── docker-compose.yml
├── Makefile
├── pyproject.toml
└── .github/workflows/assessment.yml
```

---

## Makefile Targets

```
make up        Start Docker lab (juice-shop + WAF + navigator)
make down      Stop and remove containers
make install   Create venv and install Python dependencies
make assess    Run full assessment (attack + correlate + report)
make report    Regenerate reports from most recent raw JSON
make logs      Stream WAF access log live
make clean     Delete reports/, navigator-data/, venv/
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP attack client |
| `pydantic` + `pydantic-settings` | Data models and config |
| `urllib3` | Connection pooling and retry |
| `jinja2` | HTML report templating |
| `rich` | Console output, progress bar, tables |
| `typer` | CLI framework |
| `python-dotenv` | `.env` loading |

Dev: `pytest`, `pytest-mock`, `black`, `ruff`, `mypy`

---

## License

MIT — see `LICENSE`.

---

*AegisLoop is a security research and validation tool. The authors assume no liability for misuse. Always obtain written authorization before testing any system.*
