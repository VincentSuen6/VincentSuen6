from typing import Any
from pydantic import BaseModel


class BeaconRegistration(BaseModel):
    hostname: str
    username: str
    os: str
    pid: int


class TaskCreate(BaseModel):
    beacon_id: str
    type: str
    params: dict[str, Any] = {}


class TaskResult(BaseModel):
    task_id: str
    beacon_id: str
    status: str
    output: str = ""
    telemetry: dict[str, Any] = {}
    completed_at: str
