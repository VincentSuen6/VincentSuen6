from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

import requests

from .models import AssessmentConfig, ControlStatus, FindingResult, Severity


class BaseModule(ABC):
    """Contract every attack module must satisfy."""

    technique_id: str
    technique_name: str
    owasp_category: str
    severity: Severity
    cvss_score: float

    def __init__(self, session: requests.Session, config: AssessmentConfig) -> None:
        self.session = session
        self.config = config
        self.log = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def execute(self) -> FindingResult:
        ...

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: object,
    ) -> tuple[requests.Response | None, float, str | None]:
        """Timed HTTP call. Returns (response, elapsed_ms, error_str)."""
        url = self.config.target_url.rstrip("/") + path
        start = time.monotonic()
        try:
            resp = self.session.request(
                method,
                url,
                timeout=self.config.request_timeout,
                **kwargs,  # type: ignore[arg-type]
            )
            elapsed = (time.monotonic() - start) * 1000
            self.log.debug("%s %s → %d (%.0f ms)", method, path, resp.status_code, elapsed)
            return resp, elapsed, None
        except requests.exceptions.RequestException as exc:
            elapsed = (time.monotonic() - start) * 1000
            self.log.warning("%s %s → ERROR: %s", method, path, exc)
            return None, elapsed, str(exc)

    def _build_result(
        self,
        payload: str,
        endpoint: str,
        response: requests.Response | None,
        elapsed_ms: float,
        error: str | None,
    ) -> FindingResult:
        status_code = response.status_code if response else None
        if error:
            control_status = ControlStatus.UNTESTED
        elif status_code == 403:
            control_status = ControlStatus.BLOCKED
        elif status_code in (200, 201, 301, 302, 500):
            control_status = ControlStatus.BYPASSED
        else:
            control_status = ControlStatus.UNTESTED

        return FindingResult(
            technique_id=self.technique_id,
            technique_name=self.technique_name,
            owasp_category=self.owasp_category,
            severity=self.severity,
            cvss_score=self.cvss_score,
            payload=payload,
            endpoint=endpoint,
            status_code=status_code,
            response_time_ms=round(elapsed_ms, 2),
            control_status=control_status,
            error=error,
            assessment_id=self.config.assessment_id,
        )
