from __future__ import annotations

from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

# XXE injection: POST an XML body with a DOCTYPE/ENTITY declaration to any endpoint.
# ModSecurity CRS rules 921110/921120 detect XXE patterns in raw request bodies.
# Juice Shop's login endpoint is used as a POST target — the app will reject it,
# but the WAF should intercept the XML payload before it reaches the app.
_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<foo>&xxe;</foo>"
)
_ENDPOINT = "/rest/user/login"


class XXEModule(BaseModule):
    technique_id = "T1005"
    technique_name = "Data from Local System (XXE File Read)"
    owasp_category = "A05:2021-Security Misconfiguration"
    severity = Severity.HIGH
    cvss_score = 7.5

    def execute(self) -> FindingResult:
        self.log.info("Probing %s with XXE DOCTYPE payload", _ENDPOINT)
        resp, elapsed, error = self._request(
            "POST",
            _ENDPOINT,
            data=_PAYLOAD,
            headers={"Content-Type": "application/xml"},
        )
        result = self._build_result(_PAYLOAD, _ENDPOINT, resp, elapsed, error)

        if resp and resp.status_code not in (403,):
            body = resp.text
            if "root:" in body or "/bin/bash" in body:
                result.evidence = "XXE file-read succeeded — /etc/passwd content detected in response."
            elif resp.status_code in (200, 201, 400, 500):
                result.evidence = (
                    f"XXE payload reached application (HTTP {resp.status_code}) — "
                    "WAF did not detect DOCTYPE/ENTITY declaration."
                )

        return result
