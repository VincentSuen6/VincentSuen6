from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..core.models import ControlStatus, FindingResult

log = logging.getLogger(__name__)

# ModSecurity JSON audit log fields we care about
_MODSEC_JSON_KEYS = ("request", "response", "transaction")

# Fallback Nginx combined-log status-code extraction
# Format: "METHOD /path HTTP/1.1" <STATUS> <bytes>
_NGINX_STATUS_RE = re.compile(r'"\s*(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)[^"]*"\s+(\d{3})\s')

# Attack signature → technique ID
_FINGERPRINTS: dict[str, str] = {
    # Existing modules
    r"(?:UNION\s+(?:ALL\s+)?SELECT|OR\s+1\s*=\s*1|--\s*$)": "T1190",
    r"<script\b[^>]*>": "T1059.007",
    r"(?:\.\./){2,}": "T1083",
    r"/api/Users/\d+": "T1078",
    # New modules (v2)
    r"(?:;\s*(?:cat|ls|id|whoami|uname)|[`$]\((?:id|whoami)\)|\|\s*(?:id|cat))": "T1059.004",
    r"(?:169\.254\.169\.254|file:///etc|http://(?:127\.0\.0\.1|localhost):\d+)": "T1090.001",
    r"<!DOCTYPE\s+\w+\s*\[.*?<!ENTITY": "T1005",
    r"/redirect\?to=https?://(?!juice-sh\.op)": "T1598.003",
    r"(?:\"email\":\s*\"[^\"]+\",\s*\"password\":).*(?:\"email\":\s*\"[^\"]+\",\s*\"password\":)": "T1110.004",
}


def correlate(findings: list[FindingResult], waf_log_path: str) -> list[FindingResult]:
    """Overlay WAF block/pass verdicts onto existing FindingResult objects."""
    log_file = Path(waf_log_path)
    if not log_file.exists():
        log.warning("WAF log not found at %s — control status remains UNTESTED", waf_log_path)
        return findings

    verdicts: dict[str, ControlStatus] = {}

    with log_file.open(encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue

            status_code = _extract_status(line)
            if status_code is None:
                continue

            matched_tid = _match_technique(line)
            if matched_tid is None:
                continue

            verdict = _verdict_from_status(status_code)

            existing = verdicts.get(matched_tid)
            if existing is None:
                verdicts[matched_tid] = verdict
            elif existing != verdict:
                # Conflicting verdicts across log lines → surface as PARTIAL
                verdicts[matched_tid] = ControlStatus.PARTIAL

    for finding in findings:
        if finding.technique_id in verdicts:
            finding.control_status = verdicts[finding.technique_id]

    return findings


def _extract_status(line: str) -> int | None:
    """Try JSON audit log first, fall back to Nginx combined-log regex."""
    try:
        obj = json.loads(line)
        # ModSecurity JSON audit log: transaction.response.http_code
        for key in ("transaction", "response"):
            if key in obj and isinstance(obj[key], dict):
                code = obj[key].get("http_code") or obj[key].get("status")
                if code:
                    return int(code)
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    m = _NGINX_STATUS_RE.search(line)
    if m:
        return int(m.group(1))

    return None


def _match_technique(line: str) -> str | None:
    for pattern, tid in _FINGERPRINTS.items():
        if re.search(pattern, line, re.IGNORECASE):
            return tid
    return None


def _verdict_from_status(status_code: int) -> ControlStatus:
    if status_code == 403:
        return ControlStatus.BLOCKED
    if status_code in (200, 201, 301, 302, 500):
        return ControlStatus.BYPASSED
    return ControlStatus.UNTESTED
