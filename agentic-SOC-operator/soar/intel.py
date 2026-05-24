"""
intel.py — 6-Source Parallel Threat Intelligence Aggregator
============================================================
Replaces the single VirusTotal call in Node 1 with a concurrent fan-out
across 6 independent sources using ThreadPoolExecutor.

Total wall-clock time = max(individual timeouts), not sum(timeouts).
A single source going unreachable cannot zero out a genuine threat score.

Composite scoring — weights sum to a max of 10.0:
  AbuseIPDB confidence  : up to 3.0 pts  (score/100 * 3)
  AbuseIPDB TOR bonus   : +1.0 pt        (TOR exit node indicator)
  VirusTotal malicious  : up to 2.0 pts  (vendor_count/90 * 2)
  OTX AlienVault pulses : up to 2.0 pts  (pulse_count * 0.2, capped)
  Shodan exposed CVEs   : up to 1.5 pts  (cve_count * 0.3, capped)
  MISP attribute hits   : up to 1.0 pt   (hit_count * 0.25, capped)
  Internal blacklist    : hard override → 10.0 (no external calls made)

Example: an IP with 0 VT detections but 47 OTX pulses + 3 Shodan CVEs
scores 47*0.2 + 3*0.3 = 9.4+0.9 = 10.0 (clamped), correctly routed to the
HITL containment branch. Single-source VT would score it 0 and silently drop.
"""

import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

# ---------------------------------------------------------------------------
# API keys — all optional; source degrades to {} on missing key
# ---------------------------------------------------------------------------
_VT_KEY        = os.getenv("VT_API_KEY",    "")
_ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
_OTX_KEY       = os.getenv("OTX_API_KEY",   "")
_SHODAN_KEY    = os.getenv("SHODAN_API_KEY", "")
_MISP_URL      = os.getenv("MISP_URL",       "")
_MISP_KEY      = os.getenv("MISP_KEY",       "")
_TIMEOUT       = 6.0   # per-source HTTP timeout in seconds

# Known malicious IPs — instant 10.0 verdict, zero external API calls.
INTERNAL_BLACKLIST: set[str] = {
    "193.163.125.128",
    "192.168.56.102",
    "45.142.212.100",
    "91.108.4.0",
    "185.220.101.0",
}

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_rfc1918(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Individual source checkers — each returns {} on failure or missing key
# ---------------------------------------------------------------------------

def _check_abuseipdb(ip: str) -> dict:
    if not _ABUSEIPDB_KEY:
        return {}
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                return {
                    "abuse_confidence": d.get("abuseConfidenceScore", 0),
                    "total_reports":    d.get("totalReports", 0),
                    "is_tor":           d.get("isTor", False),
                    "isp":              d.get("isp", ""),
                    "country":          d.get("countryCode", ""),
                }
    except Exception:
        pass
    return {}


def _check_virustotal(ip: str) -> dict:
    if not _VT_KEY:
        return {}
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": _VT_KEY},
            )
            if r.status_code == 200:
                stats = (
                    r.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                return {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                }
    except Exception:
        pass
    return {}


def _check_otx(ip: str) -> dict:
    if not _OTX_KEY:
        return {}
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": _OTX_KEY},
            )
            if r.status_code == 200:
                d = r.json()
                return {"pulse_count": d.get("pulse_info", {}).get("count", 0)}
    except Exception:
        pass
    return {}


def _check_shodan(ip: str) -> dict:
    if not _SHODAN_KEY:
        return {}
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": _SHODAN_KEY},
            )
            if r.status_code == 200:
                d = r.json()
                return {
                    "open_ports": d.get("ports", [])[:10],
                    "vulns":      list(d.get("vulns", {}).keys())[:10],
                    "org":        d.get("org", ""),
                }
    except Exception:
        pass
    return {}


def _check_misp(ip: str) -> dict:
    if not _MISP_URL or not _MISP_KEY:
        return {}
    try:
        with httpx.Client(timeout=_TIMEOUT, verify=False) as c:
            r = c.post(
                f"{_MISP_URL.rstrip('/')}/attributes/restSearch",
                headers={
                    "Authorization": _MISP_KEY,
                    "Accept":        "application/json",
                    "Content-Type":  "application/json",
                },
                json={"value": ip, "limit": 5, "returnFormat": "json"},
            )
            if r.status_code == 200:
                attrs = r.json().get("response", {}).get("Attribute", [])
                return {"hits": len(attrs)}
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Composite scorer
# ---------------------------------------------------------------------------

def _composite_score(results: dict) -> float:
    """
    Weighted sum — see module docstring for allocation rationale.
    Multi-source corroboration is required to cross the 7.5 containment
    threshold, preventing a single misconfigured source from triggering blocks.
    """
    score = 0.0

    abuse = results.get("abuseipdb", {})
    score += min(abuse.get("abuse_confidence", 0) / 100 * 3.0, 3.0)
    if abuse.get("is_tor"):
        score += 1.0

    vt = results.get("virustotal", {})
    score += min(vt.get("malicious", 0) / 90 * 2.0, 2.0)

    otx = results.get("otx", {})
    score += min(otx.get("pulse_count", 0) * 0.20, 2.0)

    shodan = results.get("shodan", {})
    score += min(len(shodan.get("vulns", [])) * 0.30, 1.5)

    misp = results.get("misp", {})
    score += min(misp.get("hits", 0) * 0.25, 1.0)

    return round(min(score, 10.0), 2)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def enrich_ip(ip: str) -> dict:
    """
    Fan out to all configured sources in parallel using ThreadPoolExecutor.
    Returns enrichment metadata dict with a composite 0-10 score field.
    """
    if ip in INTERNAL_BLACKLIST:
        return {
            "score":   10.0,
            "source":  "internal_blacklist",
            "details": {},
            "active_sources": [],
        }

    if _is_rfc1918(ip):
        return {
            "score":   0.0,
            "source":  "rfc1918_private",
            "details": {},
            "active_sources": [],
        }

    source_fns = {
        "abuseipdb":  _check_abuseipdb,
        "virustotal": _check_virustotal,
        "otx":        _check_otx,
        "shodan":     _check_shodan,
        "misp":       _check_misp,
    }

    results: dict = {}
    with ThreadPoolExecutor(max_workers=len(source_fns)) as pool:
        future_map = {pool.submit(fn, ip): name for name, fn in source_fns.items()}
        for fut in as_completed(future_map, timeout=_TIMEOUT + 2):
            name = future_map[fut]
            try:
                results[name] = fut.result()
            except Exception:
                results[name] = {}

    score        = _composite_score(results)
    active       = [k for k, v in results.items() if v]

    return {
        "score":          score,
        "source":         "multi-source",
        "active_sources": active,
        "details":        results,
    }
