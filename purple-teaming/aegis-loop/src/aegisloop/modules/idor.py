from __future__ import annotations

from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

# IDOR: Juice Shop exposes /api/Users/:id — an unauthenticated request to ID 1
# reveals the admin account. This maps to broken object-level authorisation (BOLA).
_ENDPOINT = "/api/Users/1"


class IDORModule(BaseModule):
    technique_id = "T1078"
    technique_name = "Valid Accounts (IDOR / BOLA)"
    owasp_category = "A01:2021-Broken Access Control"
    severity = Severity.HIGH
    cvss_score = 8.1

    def execute(self) -> FindingResult:
        self.log.info("Probing %s for unauthenticated object access", _ENDPOINT)

        resp, elapsed, error = self._request("GET", _ENDPOINT)
        result = self._build_result("GET /api/Users/1 (no auth token)", _ENDPOINT, resp, elapsed, error)

        if resp and resp.status_code == 200:
            try:
                body = resp.json()
                if "data" in body and "email" in str(body):
                    result.evidence = f"User record returned without authentication: {str(body)[:200]}"
            except Exception:
                pass

        return result
