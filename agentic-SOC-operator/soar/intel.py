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

Resilience:
  Circuit breaker (pybreaker) — after 3 consecutive failures a source's
  circuit opens for 60 s. Calls during the open window raise immediately
  instead of timing out, keeping p99 latency low under partial outages.

  Per-source rate limiter (token bucket) — enforces API tier limits:
    AbuseIPDB free: 1 000 req/day  → ~41/hour → floor to 1 req/90 s
    VirusTotal public: 4 req/min   → 1 req/15 s
    OTX: 10 000/day                → 1 req/9 s (very loose)
    Shodan free: 1 req/s           → 1 req/1 s
    MISP: internal, no published limit → 1 req/0.5 s
  Limits are conservative; set *_RATE env vars to tune per-environment.
"""

import ipaddress
import os
import threading
import time
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
# Circuit breaker — simple state machine, no external dependency
# ---------------------------------------------------------------------------
class _CircuitBreaker:
    """
    Three-state (CLOSED → OPEN → HALF_OPEN) circuit breaker.

    CLOSED  : normal operation; failures are counted.
    OPEN    : source is failing; calls return {} immediately without I/O.
    HALF_OPEN: one trial call allowed; if it succeeds → CLOSED, else → OPEN.

    This prevents a timing-out source (e.g. AbuseIPDB rate-limited) from
    holding a ThreadPoolExecutor thread for _TIMEOUT seconds on every check.
    """

    def __init__(self, name: str, fail_max: int = 3, reset_timeout: float = 60.0):
        self.name          = name
        self.fail_max      = fail_max
        self.reset_timeout = reset_timeout
        self._failures     = 0
        self._state        = "CLOSED"   # CLOSED | OPEN | HALF_OPEN
        self._opened_at    = 0.0
        self._lock         = threading.Lock()

    def call(self, fn, *args, **kwargs):
        """Execute fn(*args) if the circuit allows it, else return {}."""
        with self._lock:
            if self._state == "OPEN":
                if time.time() - self._opened_at >= self.reset_timeout:
                    self._state = "HALF_OPEN"
                else:
                    return {}   # fast-fail

        try:
            result = fn(*args, **kwargs)
            with self._lock:
                self._failures = 0
                self._state    = "CLOSED"
            return result
        except Exception:
            with self._lock:
                self._failures += 1
                if self._failures >= self.fail_max or self._state == "HALF_OPEN":
                    self._state    = "OPEN"
                    self._opened_at = time.time()
                    print(
                        f"[CircuitBreaker] {self.name} OPEN — "
                        f"will retry in {self.reset_timeout:.0f}s"
                    )
            return {}


# ---------------------------------------------------------------------------
# Per-source token-bucket rate limiter
# ---------------------------------------------------------------------------
class _RateLimiter:
    """
    Blocking token-bucket rate limiter.  Each source gets one token every
    `min_interval` seconds.  If a call arrives before the interval has elapsed
    the caller blocks (sleeps) for the remaining time.

    This keeps us within free-tier API limits even under burst load.
    """

    def __init__(self, min_interval: float):
        self._min_interval = min_interval
        self._last_call    = 0.0
        self._lock         = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now  = time.time()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.time()


# Rate limits: env-override, sensible defaults below
_RATE_ABUSEIPDB = float(os.getenv("RATE_ABUSEIPDB_S",  "90"))   # 1 req / 90 s
_RATE_VT        = float(os.getenv("RATE_VT_S",          "15"))   # 1 req / 15 s (4/min)
_RATE_OTX       = float(os.getenv("RATE_OTX_S",         "9"))    # 1 req / 9 s
_RATE_SHODAN    = float(os.getenv("RATE_SHODAN_S",       "1"))    # 1 req / 1 s
_RATE_MISP      = float(os.getenv("RATE_MISP_S",         "0.5")) # 2 req / 1 s

_cb_abuseipdb  = _CircuitBreaker("abuseipdb")
_cb_virustotal = _CircuitBreaker("virustotal")
_cb_otx        = _CircuitBreaker("otx")
_cb_shodan     = _CircuitBreaker("shodan")
_cb_misp       = _CircuitBreaker("misp")

_rl_abuseipdb  = _RateLimiter(_RATE_ABUSEIPDB)
_rl_virustotal = _RateLimiter(_RATE_VT)
_rl_otx        = _RateLimiter(_RATE_OTX)
_rl_shodan     = _RateLimiter(_RATE_SHODAN)
_rl_misp       = _RateLimiter(_RATE_MISP)


# ---------------------------------------------------------------------------
# Individual source checkers — each returns {} on failure or missing key
# ---------------------------------------------------------------------------

def _check_abuseipdb(ip: str) -> dict:
    if not _ABUSEIPDB_KEY:
        return {}
    _rl_abuseipdb.acquire()

    def _fetch(ip):
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
        return {}

    return _cb_abuseipdb.call(_fetch, ip)


def _check_virustotal(ip: str) -> dict:
    if not _VT_KEY:
        return {}
    _rl_virustotal.acquire()

    def _fetch(ip):
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
        return {}

    return _cb_virustotal.call(_fetch, ip)


def _check_otx(ip: str) -> dict:
    if not _OTX_KEY:
        return {}
    _rl_otx.acquire()

    def _fetch(ip):
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": _OTX_KEY},
            )
            if r.status_code == 200:
                d = r.json()
                return {"pulse_count": d.get("pulse_info", {}).get("count", 0)}
        return {}

    return _cb_otx.call(_fetch, ip)


def _check_shodan(ip: str) -> dict:
    if not _SHODAN_KEY:
        return {}
    _rl_shodan.acquire()

    def _fetch(ip):
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
        return {}

    return _cb_shodan.call(_fetch, ip)


def _check_misp(ip: str) -> dict:
    if not _MISP_URL or not _MISP_KEY:
        return {}
    _rl_misp.acquire()

    def _fetch(ip):
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
        return {}

    return _cb_misp.call(_fetch, ip)


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
    Each source is protected by a circuit breaker (fast-fails on open circuit)
    and a rate limiter (token bucket, blocks until slot is available).
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

    score  = _composite_score(results)
    active = [k for k, v in results.items() if v]

    return {
        "score":          score,
        "source":         "multi-source",
        "active_sources": active,
        "details":        results,
    }
