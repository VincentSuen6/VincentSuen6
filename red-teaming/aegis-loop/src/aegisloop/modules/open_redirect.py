from __future__ import annotations

import urllib.parse

from ..core.base_module import BaseModule
from ..core.models import ControlStatus, FindingResult, Severity

# Juice Shop exposes /redirect?to= and validates against a whitelist.
# A WAF with ModSecurity CRS rule 931130 should detect obvious open-redirect patterns.
# We supply an off-whitelist URL; a 301/302 to our domain = WAF bypassed.
_TARGET_URL = "https://attacker.example.com/phishing"
_ENDPOINT = "/redirect"


class OpenRedirectModule(BaseModule):
    technique_id = "T1598.003"
    technique_name = "Phishing: Spearphishing Link (Open Redirect)"
    owasp_category = "A01:2021-Broken Access Control"
    severity = Severity.MEDIUM
    cvss_score = 6.1

    def execute(self) -> FindingResult:
        self.log.info("Probing %s for open redirect to external domain", _ENDPOINT)
        encoded = urllib.parse.quote(_TARGET_URL, safe="")
        path = f"{_ENDPOINT}?to={encoded}"

        resp, elapsed, error = self._request("GET", path, allow_redirects=False)
        result = self._build_result(_TARGET_URL, _ENDPOINT, resp, elapsed, error)

        if resp is not None:
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 307, 308) and "attacker.example.com" in location:
                result.control_status = ControlStatus.BYPASSED
                result.evidence = f"Open redirect confirmed: Location → {location}"
            elif resp.status_code == 403:
                result.control_status = ControlStatus.BLOCKED
            elif resp.status_code in (200, 500):
                # App rejected it (Juice Shop returns 500 for non-whitelisted URLs)
                # but WAF did not proactively block — partial coverage
                result.control_status = ControlStatus.PARTIAL
                result.evidence = (
                    f"Redirect attempt not blocked by WAF (HTTP {resp.status_code}); "
                    "app-layer validation fired instead."
                )

        return result
