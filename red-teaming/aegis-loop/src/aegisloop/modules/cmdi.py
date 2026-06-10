from __future__ import annotations

import urllib.parse

from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

# Unix shell metacharacter injection via Juice Shop's product search endpoint.
# ModSecurity CRS rule 932100/932105 should catch shell command patterns.
_PAYLOAD = "; cat /etc/passwd"
_ENDPOINT = "/rest/products/search"


class CommandInjectionModule(BaseModule):
    technique_id = "T1059.004"
    technique_name = "Unix Shell Command Injection"
    owasp_category = "A03:2021-Injection"
    severity = Severity.CRITICAL
    cvss_score = 9.8

    def execute(self) -> FindingResult:
        self.log.info("Probing %s with shell metacharacter payload", _ENDPOINT)
        encoded = urllib.parse.quote(_PAYLOAD, safe="")
        path = f"{_ENDPOINT}?q={encoded}"

        resp, elapsed, error = self._request("GET", path)
        result = self._build_result(_PAYLOAD, _ENDPOINT, resp, elapsed, error)

        if resp and resp.status_code == 200:
            body = resp.text
            if "root:" in body or "/bin/" in body:
                result.evidence = "OS command output detected in response body — arbitrary command execution confirmed."
            else:
                result.evidence = "Shell metacharacter payload returned HTTP 200 — WAF failed to detect command injection pattern."

        return result
