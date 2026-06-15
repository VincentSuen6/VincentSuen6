"""
Bridge — orchestrates one full attack-observe cycle:

  1. Start the C2 server (subprocess)
  2. Launch the beacon (subprocess, target machine / same box in lab)
  3. Attach Frida to the beacon process
  4. Queue a TTP task via the operator API
  5. Wait for the result
  6. Collect Frida telemetry + Sysmon logs
  7. Save everything to runs/<timestamp>/

Run from C2/ directory:
    python -m bridge.bridge --ttp process_injection --params '{"target_pid": 1234}'

Requires: pip install c2-lab[bridge]
"""

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

C2_URL = os.environ.get("C2_URL", "http://127.0.0.1:8000")
RUNS_DIR = Path(__file__).parent.parent / "runs"


def _wait_for_server(timeout: int = 15) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{C2_URL}/beacons", timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("C2 server did not start in time")


def _wait_for_beacon(timeout: int = 20) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{C2_URL}/beacons", timeout=5)
        beacons = r.json()["beacons"]
        if beacons:
            return beacons[0]["beacon_id"]
        time.sleep(1)
    raise RuntimeError("No beacon registered in time")


def _queue_task(beacon_id: str, ttp: str, params: dict) -> str:
    r = requests.post(
        f"{C2_URL}/tasks",
        json={"beacon_id": beacon_id, "type": ttp, "params": params},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["task_id"]


def _wait_for_result(task_id: str, timeout: int = 60) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{C2_URL}/results", timeout=5)
        for result in r.json()["results"]:
            if result["task_id"] == task_id:
                return result
        time.sleep(1)
    return None


def _attach_frida(pid: int, hook_script: Path) -> tuple:
    """Attach Frida and return (session, script). Requires frida package."""
    import frida  # deferred import — only needed when bridge runs with [bridge] extras

    collected: list[dict] = []

    def on_message(message, _data):
        if message.get("type") == "send":
            collected.append(message["payload"])

    session = frida.attach(pid)
    script = session.create_script(hook_script.read_text())
    script.on("message", on_message)
    script.load()
    return session, script, collected


def run(ttp: str, params: dict, with_frida: bool = False) -> None:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "_" + ttp
    out_dir = RUNS_DIR / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[bridge] run_id={run_id}  ttp={ttp}  out={out_dir}")

    server_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server.main:app", "--port", "8000"],
        cwd=Path(__file__).parent.parent,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_for_server()
        print("[bridge] server ready")

        beacon_proc = subprocess.Popen(
            [sys.executable, "-m", "beacon.beacon"],
            cwd=Path(__file__).parent.parent,
            env={**os.environ, "C2_URL": C2_URL, "C2_SLEEP": "2", "C2_JITTER": "0"},
        )

        frida_session = frida_script = frida_events = None
        if with_frida:
            hook_path = Path(__file__).parent / "frida_hooks" / f"{ttp}.js"
            if hook_path.exists():
                time.sleep(1)  # let beacon register before we attach
                frida_session, frida_script, frida_events = _attach_frida(
                    beacon_proc.pid, hook_path
                )
                print(f"[bridge] frida attached to PID {beacon_proc.pid}")

        beacon_id = _wait_for_beacon()
        print(f"[bridge] beacon registered  id={beacon_id}")

        task_id = _queue_task(beacon_id, ttp, params)
        print(f"[bridge] task queued  id={task_id}")

        result = _wait_for_result(task_id)
        if result is None:
            print("[bridge] TIMEOUT waiting for result")
        else:
            print(f"[bridge] result  status={result['status']}")
            (out_dir / "result.json").write_text(json.dumps(result, indent=2))

        if frida_events is not None:
            time.sleep(1)  # let Frida flush remaining messages
            (out_dir / "frida_telemetry.json").write_text(json.dumps(frida_events, indent=2))
            frida_script.unload()
            frida_session.detach()

        print(f"[bridge] artifacts saved to {out_dir}")

    finally:
        beacon_proc.terminate()
        server_proc.terminate()


def main() -> None:
    parser = argparse.ArgumentParser(prog="bridge")
    parser.add_argument("--ttp", required=True, help="TTP module name")
    parser.add_argument("--params", default="{}", help="JSON params")
    parser.add_argument("--frida", action="store_true", help="attach Frida if hook script exists")
    args = parser.parse_args()
    run(args.ttp, json.loads(args.params), with_frida=args.frida)


if __name__ == "__main__":
    main()
