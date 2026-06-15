from __future__ import annotations

from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

# SSRF probe via Juice Shop's feedback comment field.
# The WAF (CRS rule 934100) should detect cloud metadata endpoint patterns.
# A 200/201 response means the payload reached the app without WAF interception.
_PAYLOAD = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
_ENDPOINT = "/api/Feedbacks"


class SSRFModule(BaseModule):
    technique_id = "T1090.001"
    technique_name = "Internal Proxy (SSRF — Cloud Metadata)"
    owasp_category = "A10:2021-SSRF"
    severity = Severity.HIGH
    cvss_score = 8.8

    def execute(self) -> FindingResult:
        self.log.info("Probing %s with SSRF cloud-metadata payload", _ENDPOINT)
        resp, elapsed, error = self._request(
            "POST",
            _ENDPOINT,
            json={
                "UserId": None,
                "captchaId": 0,
                "captchaSolution": "1",
                "comment": _PAYLOAD,
                "rating": 1,
            },
        )
        result = self._build_result(_PAYLOAD, _ENDPOINT, resp, elapsed, error)

        if resp and resp.status_code in (200, 201):
            result.evidence = (
                "Feedback with SSRF cloud-metadata URL accepted (HTTP "
                f"{resp.status_code}) — WAF did not block internal metadata probe."
            )

        return result
