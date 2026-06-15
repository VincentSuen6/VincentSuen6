"""
tests/test_intel.py — Unit tests for intel.py
==============================================
These tests run without network access. All external HTTP calls are patched.
Run with:  pytest soar/tests/test_intel.py -v
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Allow importing from soar/ without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))

import intel


# ---------------------------------------------------------------------------
# INTERNAL_BLACKLIST
# ---------------------------------------------------------------------------

def test_blacklist_returns_score_10():
    ip = "45.142.212.100"
    assert ip in intel.INTERNAL_BLACKLIST
    result = intel.enrich_ip(ip)
    assert result["score"] == 10.0
    assert result["source"] == "internal_blacklist"
    assert result["active_sources"] == []


def test_blacklist_skips_external_calls():
    ip = "45.142.212.100"
    with patch("intel._check_virustotal") as mock_vt:
        intel.enrich_ip(ip)
        mock_vt.assert_not_called()


# ---------------------------------------------------------------------------
# RFC 1918 private addresses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.255.255",
])
def test_rfc1918_returns_score_0(ip):
    result = intel.enrich_ip(ip)
    assert result["score"] == 0.0
    assert result["source"] == "rfc1918_private"


# ---------------------------------------------------------------------------
# Composite scorer
# ---------------------------------------------------------------------------

def test_composite_score_empty_sources():
    score = intel._composite_score({})
    assert score == 0.0


def test_composite_score_abuseipdb_only():
    results = {
        "abuseipdb": {"abuse_confidence": 100, "is_tor": False},
    }
    score = intel._composite_score(results)
    assert score == 3.0


def test_composite_score_tor_bonus():
    results = {
        "abuseipdb": {"abuse_confidence": 100, "is_tor": True},
    }
    score = intel._composite_score(results)
    assert score == 4.0


def test_composite_score_max_capped_at_10():
    results = {
        "abuseipdb":  {"abuse_confidence": 100, "is_tor": True},
        "virustotal": {"malicious": 90},
        "otx":        {"pulse_count": 100},
        "shodan":     {"vulns": ["CVE-2024-1234"] * 20},
        "misp":       {"hits": 10},
    }
    score = intel._composite_score(results)
    assert score == 10.0


def test_composite_score_partial_sources():
    results = {
        "virustotal": {"malicious": 45},  # 45/90 * 2 = 1.0
        "otx":        {"pulse_count": 5}, # 5 * 0.2 = 1.0
    }
    score = intel._composite_score(results)
    assert abs(score - 2.0) < 0.01


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

def test_circuit_breaker_opens_after_fail_max():
    cb = intel._CircuitBreaker("test-cb", fail_max=2, reset_timeout=60.0)

    def _always_fails(*_):
        raise RuntimeError("down")

    cb.call(_always_fails, "x")
    assert cb._state == "CLOSED"
    cb.call(_always_fails, "x")
    assert cb._state == "OPEN"


def test_circuit_breaker_fast_returns_empty_when_open():
    cb = intel._CircuitBreaker("test-cb", fail_max=1, reset_timeout=9999.0)

    def _always_fails(*_):
        raise RuntimeError("down")

    cb.call(_always_fails, "x")   # trips open
    assert cb._state == "OPEN"

    call_count = 0

    def _track(*_):
        nonlocal call_count
        call_count += 1
        return {"data": True}

    result = cb.call(_track, "x")
    assert result == {}
    assert call_count == 0           # fn was never called (fast-fail)


def test_circuit_breaker_resets_on_success():
    cb = intel._CircuitBreaker("test-cb", fail_max=1, reset_timeout=0.0)

    def _always_fails(*_):
        raise RuntimeError("down")

    cb.call(_always_fails, "x")   # trips open
    # reset_timeout=0 → next call transitions to HALF_OPEN
    result = cb.call(lambda _: {"ok": True}, "x")
    assert result == {"ok": True}
    assert cb._state == "CLOSED"


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

def test_rate_limiter_blocks_between_calls():
    import time
    rl = intel._RateLimiter(min_interval=0.05)
    t0 = time.time()
    rl.acquire()
    rl.acquire()
    elapsed = time.time() - t0
    assert elapsed >= 0.04   # at least one interval must have passed


# ---------------------------------------------------------------------------
# enrich_ip fan-out with mocked sources
# ---------------------------------------------------------------------------

@patch("intel._check_abuseipdb", return_value={"abuse_confidence": 80, "is_tor": False, "total_reports": 5, "isp": "AS1234", "country": "RU"})
@patch("intel._check_virustotal", return_value={"malicious": 20, "suspicious": 2, "harmless": 50})
@patch("intel._check_otx",        return_value={"pulse_count": 3})
@patch("intel._check_shodan",     return_value={"open_ports": [22, 80], "vulns": ["CVE-2021-44228"], "org": "Acme"})
@patch("intel._check_misp",       return_value={"hits": 2})
def test_enrich_ip_aggregates_sources(mock_misp, mock_shodan, mock_otx, mock_vt, mock_abuse):
    result = intel.enrich_ip("8.8.8.8")   # public IP, not in blacklist
    assert result["score"] > 0
    assert result["source"] == "multi-source"
    assert len(result["active_sources"]) > 0
    assert "details" in result


@patch("intel._check_abuseipdb", return_value={})
@patch("intel._check_virustotal", return_value={})
@patch("intel._check_otx",       return_value={})
@patch("intel._check_shodan",    return_value={})
@patch("intel._check_misp",      return_value={})
def test_enrich_ip_all_sources_empty_gives_score_0(*_):
    result = intel.enrich_ip("8.8.8.8")
    assert result["score"] == 0.0
    assert result["active_sources"] == []
