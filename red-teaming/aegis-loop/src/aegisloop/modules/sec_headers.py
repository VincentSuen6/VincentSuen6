from __future__ import annotations

from ..core.base_module import BaseModule
from ..core.models import ControlStatus, FindingResult, Severity

# Security headers audit: issue a plain GET / and check for presence of defensive
# HTTP response headers. Missing headers are a configuration gap, not an injection
# vector, so we bypass the standard _build_result() status-code logic.
_ENDPOINT = "/"
_REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


class SecurityHeadersModule(BaseModule):
    technique_id = "T1562.001"
    technique_name = "Impair Defenses: Missing Security Headers"
    owasp_category = "A05:2021-Security Misconfiguration"
    severity = Severity.MEDIUM
    cvss_score = 5.3

    def execute(self) -> FindingResult:
        self.log.info("Auditing security response headers on %s", _ENDPOINT)
        resp, elapsed, error = self._request("GET", _ENDPOINT)

        if error or resp is None:
            return FindingResult(
                technique_id=self.technique_id,
                technique_name=self.technique_name,
                owasp_category=self.owasp_category,
                severity=self.severity,
                cvss_score=self.cvss_score,
                payload="HEAD check",
                endpoint=_ENDPOINT,
                response_time_ms=round(elapsed, 2),
                control_status=ControlStatus.UNTESTED,
                error=error,
                assessment_id=self.config.assessment_id,
            )

        present = {h.lower() for h in resp.headers}
        missing = [h for h in _REQUIRED_HEADERS if h.lower() not in present]

        if missing:
            status = ControlStatus.BYPASSED
            evidence = f"Missing headers: {', '.join(missing)}"
        else:
            status = ControlStatus.BLOCKED
            evidence = ""

        return FindingResult(
            technique_id=self.technique_id,
            technique_name=self.technique_name,
            owasp_category=self.owasp_category,
            severity=self.severity,
            cvss_score=self.cvss_score,
            payload=f"GET {_ENDPOINT} (header audit)",
            endpoint=_ENDPOINT,
            status_code=resp.status_code,
            response_time_ms=round(elapsed, 2),
            control_status=status,
            evidence=evidence,
            assessment_id=self.config.assessment_id,
        )
