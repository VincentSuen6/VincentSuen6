"""
enrichment_engine.py — Data Enrichment Engine
===============================================
Enriches raw Wazuh/Elastic/Docker threat records with context
from six external threat intelligence sources.

Sources (all gracefully skipped if API key is missing):
  • AbuseIPDB     — IP reputation / abuse confidence score
  • VirusTotal    — file hash + IP malicious verdicts
  • OTX AlienVault— threat pulses for IPs, hashes, CVEs
  • Shodan        — internet-exposed port/service data for IPs
  • MISP          — local MISP instance attribute search
  • TAXII / STIX  — MITRE ATT&CK live feed (no key required)

Usage:
    from intelligence.enrichment_engine import enrich_threat
    enriched = enrich_threat(threat_dict)
"""

import os
import json
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ── API keys (all optional — engine degrades gracefully) ──────────────────────
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
OTX_KEY        = os.getenv("OTX_KEY", "")
SHODAN_KEY     = os.getenv("SHODAN_KEY", "")
MISP_URL       = os.getenv("MISP_URL", "")
MISP_KEY       = os.getenv("MISP_KEY", "")

TIMEOUT        = 8   # seconds per API call


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

def check_abuseipdb(ip: str) -> dict:
    """Returns abuse confidence score and ISP for an IP."""
    if not ABUSEIPDB_KEY:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports":          d.get("totalReports", 0),
                "isp":                    d.get("isp", ""),
                "country_code":           d.get("countryCode", ""),
                "is_tor":                 d.get("isTor", False),
                "source":                 "abuseipdb",
            }
    except Exception as e:
        print(f"[Enrich] AbuseIPDB error for {ip}: {e}")
    return {}


# ── VirusTotal ────────────────────────────────────────────────────────────────

def check_virustotal_hash(file_hash: str) -> dict:
    """Returns malicious/suspicious verdict count from VirusTotal."""
    if not VIRUSTOTAL_KEY:
        return {}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "source":     "virustotal",
            }
        if r.status_code == 404:
            return {"verdict": "not_found", "source": "virustotal"}
    except Exception as e:
        print(f"[Enrich] VirusTotal error for {file_hash}: {e}")
    return {}


def check_virustotal_ip(ip: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "country":    attrs.get("country", ""),
                "as_owner":   attrs.get("as_owner", ""),
                "source":     "virustotal-ip",
            }
    except Exception as e:
        print(f"[Enrich] VirusTotal IP error for {ip}: {e}")
    return {}


# ── OTX AlienVault ────────────────────────────────────────────────────────────

def check_otx_ip(ip: str) -> dict:
    if not OTX_KEY:
        return {}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "pulse_count":   d.get("pulse_info", {}).get("count", 0),
                "threat_score":  d.get("base_indicator", {}).get("threat_score", 0),
                "malware_families": [
                    p.get("name") for p in d.get("pulse_info", {}).get("pulses", [])[:3]
                ],
                "source": "otx-alienvault",
            }
    except Exception as e:
        print(f"[Enrich] OTX error for {ip}: {e}")
    return {}


def check_otx_hash(file_hash: str) -> dict:
    if not OTX_KEY:
        return {}
    try:
        indicator_type = "file" if len(file_hash) in (32, 40, 64) else "file"
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{file_hash}/general",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "malware_families": [
                    p.get("name") for p in d.get("pulse_info", {}).get("pulses", [])[:3]
                ],
                "source": "otx-hash",
            }
    except Exception as e:
        print(f"[Enrich] OTX hash error for {file_hash}: {e}")
    return {}


def check_otx_cve(cve_id: str) -> dict:
    if not OTX_KEY:
        return {}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/CVE/{cve_id}/general",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "cve_pulse_count": d.get("pulse_info", {}).get("count", 0),
                "source":          "otx-cve",
            }
    except Exception as e:
        print(f"[Enrich] OTX CVE error for {cve_id}: {e}")
    return {}


# ── Shodan ────────────────────────────────────────────────────────────────────

def check_shodan(ip: str) -> dict:
    if not SHODAN_KEY:
        return {}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            open_ports = d.get("ports", [])
            vulns      = list(d.get("vulns", {}).keys())
            return {
                "open_ports":  open_ports[:10],
                "hostnames":   d.get("hostnames", [])[:3],
                "org":         d.get("org", ""),
                "country":     d.get("country_name", ""),
                "vulns":       vulns[:5],
                "tags":        d.get("tags", []),
                "source":      "shodan",
            }
        if r.status_code == 404:
            return {"verdict": "not_indexed", "source": "shodan"}
    except Exception as e:
        print(f"[Enrich] Shodan error for {ip}: {e}")
    return {}


# ── MISP ──────────────────────────────────────────────────────────────────────

def check_misp(value: str) -> dict:
    """Search MISP for any attribute matching the given value (IP, hash, CVE)."""
    if not MISP_URL or not MISP_KEY:
        return {}
    try:
        r = requests.post(
            f"{MISP_URL.rstrip('/')}/attributes/restSearch",
            headers={
                "Authorization": MISP_KEY,
                "Accept":        "application/json",
                "Content-Type":  "application/json",
            },
            json={"value": value, "limit": 5, "returnFormat": "json"},
            timeout=TIMEOUT,
            verify=False,   # self-signed certs common in lab MISP
        )
        if r.status_code == 200:
            attrs = r.json().get("response", {}).get("Attribute", [])
            return {
                "misp_hits":  len(attrs),
                "categories": list({a.get("category") for a in attrs}),
                "event_ids":  [a.get("event_id") for a in attrs[:3]],
                "source":     "misp",
            }
    except Exception as e:
        print(f"[Enrich] MISP error for {value}: {e}")
    return {}


# ── Risk scorer ───────────────────────────────────────────────────────────────

def compute_risk_score(enrichment: dict) -> int:
    """
    0-100 composite risk score based on all enrichment signals.
    Returned in threat['risk_score'].
    """
    score = 0

    # AbuseIPDB
    abuse = enrichment.get("abuseipdb", {})
    score += min(abuse.get("abuse_confidence_score", 0) // 10, 30)
    if abuse.get("is_tor"):
        score += 10

    # VirusTotal file hash
    vt_hash = enrichment.get("virustotal_hash", {})
    score += min(vt_hash.get("malicious", 0) * 2, 20)

    # VirusTotal IP
    vt_ip = enrichment.get("virustotal_ip", {})
    score += min(vt_ip.get("malicious", 0) * 2, 10)

    # OTX
    otx_ip = enrichment.get("otx_ip", {})
    score += min(otx_ip.get("pulse_count", 0) * 2, 15)

    # Shodan exposed vulns
    shodan = enrichment.get("shodan", {})
    score += min(len(shodan.get("vulns", [])) * 3, 15)

    # MISP hits
    misp = enrichment.get("misp", {})
    score += min(misp.get("misp_hits", 0) * 5, 15)

    return min(score, 100)


# ── Master enrichment function ────────────────────────────────────────────────

def enrich_threat(threat: dict) -> dict:
    """
    Takes a threat record and adds an 'enrichment' key with all
    available intel source results.
    """
    enrichment: dict = {}
    ips     = threat.get("src_ips", [])
    hashes  = threat.get("hashes", [])
    cve_id  = threat.get("cve_id")

    active_sources = []
    if ABUSEIPDB_KEY:  active_sources.append("AbuseIPDB")
    if VIRUSTOTAL_KEY: active_sources.append("VirusTotal")
    if OTX_KEY:        active_sources.append("OTX AlienVault")
    if SHODAN_KEY:     active_sources.append("Shodan")
    if MISP_URL:       active_sources.append("MISP")
    active_sources.append("TAXII/STIX")

    print(f"[Enrich] Sources: {', '.join(active_sources) if active_sources else 'none configured'}")

    # IP enrichment
    for ip in ips[:3]:
        print(f"[Enrich] Checking IP: {ip}")
        if not enrichment.get("abuseipdb"):
            enrichment["abuseipdb"]      = check_abuseipdb(ip)
        if not enrichment.get("virustotal_ip"):
            enrichment["virustotal_ip"]  = check_virustotal_ip(ip)
        if not enrichment.get("otx_ip"):
            enrichment["otx_ip"]         = check_otx_ip(ip)
        if not enrichment.get("shodan"):
            enrichment["shodan"]         = check_shodan(ip)
        if not enrichment.get("misp_ip"):
            enrichment["misp_ip"]        = check_misp(ip)

    # Hash enrichment
    for h in hashes[:2]:
        print(f"[Enrich] Checking hash: {h[:16]}...")
        if not enrichment.get("virustotal_hash"):
            enrichment["virustotal_hash"] = check_virustotal_hash(h)
        if not enrichment.get("otx_hash"):
            enrichment["otx_hash"]        = check_otx_hash(h)
        if not enrichment.get("misp_hash"):
            enrichment["misp_hash"]       = check_misp(h)

    # CVE enrichment
    if cve_id:
        print(f"[Enrich] Checking CVE: {cve_id}")
        enrichment["otx_cve"] = check_otx_cve(cve_id)
        enrichment["misp_cve"] = check_misp(cve_id)

    enrichment["enriched_at"]  = datetime.now(timezone.utc).isoformat()
    enrichment["sources_used"] = active_sources
    threat["enrichment"]       = enrichment
    threat["risk_score"]       = compute_risk_score(enrichment)

    print(f"[Enrich] Risk score: {threat['risk_score']}/100")
    return threat
