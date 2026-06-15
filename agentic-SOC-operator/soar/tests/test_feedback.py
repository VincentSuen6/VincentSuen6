"""
tests/test_feedback.py — Unit tests for feedback.py
====================================================
Tests the threshold reader and adaptive logic without a live Redis or
PostgreSQL connection — both are patched.

Run with:  pytest soar/tests/test_feedback.py -v
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# get_threshold — reads from Redis, falls back to env default
# ---------------------------------------------------------------------------

def test_get_threshold_reads_from_redis():
    with patch("feedback.r_client") as mock_redis:
        mock_redis.get.return_value = "8.5"
        import feedback
        assert feedback.get_threshold() == 8.5


def test_get_threshold_falls_back_to_default_when_redis_empty():
    with patch("feedback.r_client") as mock_redis:
        mock_redis.get.return_value = None
        import feedback
        # Default is 7.5 unless THREAT_SCORE_THRESHOLD env var is set
        assert feedback.get_threshold() == feedback._THRESHOLD_DEFAULT


def test_get_threshold_returns_float():
    with patch("feedback.r_client") as mock_redis:
        mock_redis.get.return_value = "9.0"
        import feedback
        result = feedback.get_threshold()
        assert isinstance(result, float)


# ---------------------------------------------------------------------------
# _severity_to_int in thehive.py
# ---------------------------------------------------------------------------

def test_thehive_severity_mapping():
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import thehive
    assert thehive._severity_to_int(9.5) == 4   # Critical
    assert thehive._severity_to_int(8.0) == 3   # High
    assert thehive._severity_to_int(5.0) == 2   # Medium
    assert thehive._severity_to_int(2.0) == 1   # Low
    assert thehive._severity_to_int(0.0) == 1   # Low


# ---------------------------------------------------------------------------
# Circuit breaker state transitions (also exercises intel.py indirectly)
# ---------------------------------------------------------------------------

def test_circuit_breaker_closed_state_by_default():
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from intel import _CircuitBreaker
    cb = _CircuitBreaker("test", fail_max=3)
    assert cb._state == "CLOSED"
    assert cb._failures == 0


def test_circuit_breaker_increments_failure_count():
    from intel import _CircuitBreaker
    cb = _CircuitBreaker("test", fail_max=5)

    def _bad(_): raise RuntimeError("err")

    cb.call(_bad, "x")
    assert cb._failures == 1
    assert cb._state == "CLOSED"


# ---------------------------------------------------------------------------
# auth.py — key validation logic
# ---------------------------------------------------------------------------

def test_auth_middleware_loads_keys_from_env():
    import importlib, os
    os.environ["SOAR_API_KEYS"] = "key-aaa,key-bbb"
    import auth
    importlib.reload(auth)
    assert "key-aaa" in auth._VALID_KEYS
    assert "key-bbb" in auth._VALID_KEYS
    del os.environ["SOAR_API_KEYS"]


def test_auth_middleware_strips_whitespace():
    import importlib, os
    os.environ["SOAR_API_KEYS"] = " key-ccc , key-ddd "
    import auth
    importlib.reload(auth)
    assert "key-ccc" in auth._VALID_KEYS
    assert "key-ddd" in auth._VALID_KEYS
    del os.environ["SOAR_API_KEYS"]


def test_auth_middleware_empty_env_gives_empty_set():
    import importlib, os
    os.environ["SOAR_API_KEYS"] = ""
    import auth
    importlib.reload(auth)
    assert len(auth._VALID_KEYS) == 0
    del os.environ["SOAR_API_KEYS"]
