from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ControlStatus(str, Enum):
    BLOCKED = "BLOCKED"      # WAF returned 403 — control is effective
    BYPASSED = "BYPASSED"    # Payload reached the app (200/500) — gap confirmed
    PARTIAL = "PARTIAL"      # Mixed signals across retries
    UNTESTED = "UNTESTED"    # No WAF log entry correlated


class FindingResult(BaseModel):
    technique_id: str
    technique_name: str
    owasp_category: str
    severity: Severity
    cvss_score: float = Field(ge=0.0, le=10.0)
    payload: str
    endpoint: str
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    control_status: ControlStatus = ControlStatus.UNTESTED
    evidence: str = ""
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assessment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def is_gap(self) -> bool:
        return self.control_status in (ControlStatus.BYPASSED, ControlStatus.UNTESTED)

    @property
    def navigator_color(self) -> str:
        return {
            ControlStatus.BLOCKED: "#33cc33",
            ControlStatus.BYPASSED: "#ff3333",
            ControlStatus.PARTIAL: "#ff9900",
            ControlStatus.UNTESTED: "#aaaaaa",
        }[self.control_status]


class AssessmentConfig(BaseModel):
    target_url: str
    request_timeout: int = 10
    rate_limit_delay: float = 0.5
    assessor: str = "Purple Team"
    assessment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_dir: str = "./reports"
    navigator_dir: str = "./navigator-data"
    waf_log_path: str = "./waf-logs/access.log"
