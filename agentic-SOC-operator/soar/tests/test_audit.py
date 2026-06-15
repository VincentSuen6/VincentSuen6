"""
tests/test_audit.py — Unit tests for audit.py
==============================================
Tests the PII scrubber and Merkle hash function in isolation — no database
connection required for these pure-function tests.

Run with:  pytest soar/tests/test_audit.py -v
"""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import audit


# ---------------------------------------------------------------------------
# PII scrubber
# ---------------------------------------------------------------------------

def test_scrub_email():
    result = audit.scrub_pii("analyst@example.com triggered alert")
    assert "[REDACTED-EMAIL]" in result
    assert "analyst@example.com" not in result


def test_scrub_rfc1918_ip():
    for ip in ["10.0.0.1", "172.16.4.5", "192.168.1.100"]:
        result = audit.scrub_pii(f"connection from {ip}")
        assert "[REDACTED-IP]" in result
        assert ip not in result


def test_public_ip_not_scrubbed():
    ip = "45.142.212.100"
    result = audit.scrub_pii(f"attacker ip={ip}")
    assert ip in result
    assert "[REDACTED-IP]" not in result


def test_scrub_nested_dict():
    payload = {
        "analyst": "alice@corp.local",
        "src":     "10.0.0.5",
        "dst":     "1.2.3.4",
        "meta":    {"relay": "192.168.1.1"},
    }
    clean = audit.scrub_pii(payload)
    assert clean["analyst"] == "[REDACTED-EMAIL]"
    assert clean["src"]     == "[REDACTED-IP]"
    assert clean["dst"]     == "1.2.3.4"
    assert clean["meta"]["relay"] == "[REDACTED-IP]"


def test_scrub_list():
    data = ["192.168.0.1", "8.8.8.8", "admin@lab.internal"]
    clean = audit.scrub_pii(data)
    assert clean[0] == "[REDACTED-IP]"
    assert clean[1] == "8.8.8.8"
    assert clean[2] == "[REDACTED-EMAIL]"


def test_scrub_does_not_mutate_original():
    original = {"ip": "192.168.1.1"}
    audit.scrub_pii(original)
    assert original["ip"] == "192.168.1.1"


def test_scrub_passthrough_int_float():
    assert audit.scrub_pii(42)    == 42
    assert audit.scrub_pii(3.14)  == 3.14
    assert audit.scrub_pii(None)  is None


# ---------------------------------------------------------------------------
# Merkle hash computation
# ---------------------------------------------------------------------------

def test_compute_row_hash_is_deterministic():
    h1 = audit._compute_row_hash(1, "2024-01-01T00:00:00", "INC-001", '{"key":"val"}', "GENESIS")
    h2 = audit._compute_row_hash(1, "2024-01-01T00:00:00", "INC-001", '{"key":"val"}', "GENESIS")
    assert h1 == h2


def test_compute_row_hash_changes_on_field_mutation():
    base   = audit._compute_row_hash(1, "2024-01-01", "INC-001", '{"k":"v"}', "GENESIS")
    tamper = audit._compute_row_hash(1, "2024-01-01", "INC-001", '{"k":"X"}', "GENESIS")
    assert base != tamper


def test_compute_row_hash_chains_prev_hash():
    h1 = audit._compute_row_hash(1, "2024-01-01", "INC-001", '{}', "GENESIS")
    h2 = audit._compute_row_hash(2, "2024-01-02", "INC-001", '{}', h1)
    h3 = audit._compute_row_hash(3, "2024-01-03", "INC-001", '{}', h2)
    # Mutate row 1's hash and verify row 3 no longer validates
    bad_h2 = audit._compute_row_hash(2, "2024-01-02", "INC-001", '{}', "tampered")
    assert bad_h2 != h2   # chain is broken


def test_genesis_hash_constant():
    expected = hashlib.sha256(b"GENESIS").hexdigest()
    assert audit._GENESIS_HASH == expected
