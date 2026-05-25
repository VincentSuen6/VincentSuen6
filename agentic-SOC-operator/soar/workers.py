"""
workers.py — Semantic Deduplication Worker
==========================================
Sits between raw RabbitMQ ingestion and the LangGraph/Celery tier.
Converts alert text to dense vector embeddings and checks them against a
Qdrant collection for cluster membership.

Replaces the previous in-process list with Qdrant so that:
  1. State survives worker restarts (persisted to disk inside Qdrant container).
  2. Multiple parallel worker containers query the same vector index concurrently.
  3. Lookback window is enforced via timestamp payload filtering, not manual eviction.
"""

import ipaddress
import json
import os
import time
import uuid

import pika
import redis
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    PointStruct,
    Range,
    VectorParams,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_QDRANT_HOST        = os.getenv("QDRANT_HOST",               "localhost")
_QDRANT_PORT        = int(os.getenv("QDRANT_PORT",           "6333"))
_RABBITMQ_HOST      = os.getenv("RABBITMQ_HOST",             "localhost")
_REDIS_HOST         = os.getenv("REDIS_HOST",                "localhost")
_COLLECTION         = "incident_vectors"
_VECTOR_DIM         = 384       # all-MiniLM-L6-v2 output dimension
_SIMILARITY_THRESH  = float(os.getenv("SIMILARITY_THRESHOLD",     "0.90"))
_LOOKBACK_SECONDS   = int(os.getenv("LOOKBACK_WINDOW_SECONDS",    "600"))
_BRUTE_FORCE_SIGNAL = "failed password"

# DRY_RUN=true (default) disables the fast-path iptables block.
# Set DRY_RUN=false only in production after testing — the fast-path fires
# BEFORE the HITL gate, so it blocks without human approval.
_DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_rfc1918(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True   # treat unparseable IPs as private — fail safe

# ---------------------------------------------------------------------------
# Infrastructure clients
# ---------------------------------------------------------------------------
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
r_client        = redis.Redis(host=_REDIS_HOST, port=6379, db=1, decode_responses=True)
qdrant          = QdrantClient(host=_QDRANT_HOST, port=_QDRANT_PORT)


def _ensure_collection() -> None:
    """
    Creates the Qdrant collection on first run (idempotent).
    COSINE distance matches the similarity metric used by SentenceTransformers —
    their embeddings are L2-normalised so cosine and dot-product are equivalent,
    but naming it COSINE documents intent explicitly.
    """
    existing = {c.name for c in qdrant.get_collections().collections}
    if _COLLECTION not in existing:
        qdrant.create_collection(
            collection_name=_COLLECTION,
            vectors_config=VectorParams(size=_VECTOR_DIM, distance=Distance.COSINE),
        )
        print(f"[Qdrant] Created collection '{_COLLECTION}' ({_VECTOR_DIM}-dim, COSINE).")


_ensure_collection()


# ---------------------------------------------------------------------------
# Semantic deduplication
# ---------------------------------------------------------------------------
def evaluate_semantic_incident(alert: dict) -> tuple[bool, str]:
    """
    Encodes the alert text and searches Qdrant for an existing vector within
    the lookback window that is >= _SIMILARITY_THRESH similar.

    Returns (is_duplicate, master_incident_id).

    Why Qdrant over in-process sets:
      - Multiple worker containers share one consistent vector index.
      - Time-range payload filter enforces the lookback window server-side.
      - Qdrant persists to disk — rolling deployments don't reset dedup state.
    """
    alert_text = f"{alert.get('alert_type', '')} {alert.get('raw_log', '')}"
    new_vector = embedding_model.encode(alert_text).tolist()
    cutoff_ts  = time.time() - _LOOKBACK_SECONDS

    results = qdrant.search(
        collection_name=_COLLECTION,
        query_vector=new_vector,
        limit=1,
        score_threshold=_SIMILARITY_THRESH,
        query_filter=Filter(
            must=[FieldCondition(key="timestamp", range=Range(gte=cutoff_ts))]
        ),
    )

    if results:
        master_id = results[0].payload["master_id"]
        return True, master_id

    # New unique pattern — insert into Qdrant for future comparisons.
    master_id = f"INC-{alert.get('alert_id', uuid.uuid4().hex[:8])}"
    qdrant.upsert(
        collection_name=_COLLECTION,
        points=[
            PointStruct(
                id=str(uuid.uuid4()),
                vector=new_vector,
                payload={
                    "master_id": master_id,
                    "ip":        alert.get("source_ip", ""),
                    "timestamp": time.time(),
                },
            )
        ],
    )
    return False, master_id


# ---------------------------------------------------------------------------
# Active response — fast-path for obvious brute-force signals
# (bypasses LangGraph for instant block before VT lookup completes)
#
# SECURITY CONSTRAINTS (must all pass before any subprocess call):
#   1. DRY_RUN must be false — opt-in, not opt-out
#   2. IP must parse as a valid address
#   3. IP must not be RFC 1918 — never block internal addresses
# ---------------------------------------------------------------------------
def execute_active_response(attacker_ip: str) -> None:
    import subprocess

    if _DRY_RUN:
        print(f"[DRY_RUN] Would fast-path block {attacker_ip} — set DRY_RUN=false to enable.")
        return

    try:
        addr = ipaddress.ip_address(attacker_ip)
    except ValueError:
        r_client.incr("metric:error_logs")
        print(f"[FastPath] Rejected: {attacker_ip!r} is not a valid IP address.")
        return

    if _is_rfc1918(attacker_ip):
        r_client.incr("metric:error_logs")
        print(f"[FastPath] Rejected: {attacker_ip} is an RFC 1918 address. Never fast-path block internal IPs.")
        return

    # IP is a discrete kernel argument in array form — not shell-interpolated.
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", str(addr), "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        r_client.incr("metric:contained_hosts")
        print(f"[FastPath] iptables DROP applied to {attacker_ip}.")
    except subprocess.CalledProcessError as exc:
        r_client.incr("metric:error_logs")
        stderr = exc.stderr.decode(errors="replace") if exc.stderr else "unknown"
        print(f"[FastPath] iptables failed for {attacker_ip}: {stderr}")


# ---------------------------------------------------------------------------
# RabbitMQ consumer
# ---------------------------------------------------------------------------
def on_message_callback(ch, method, _properties, body):
    from tasks import celery_app   # imported here to avoid circular imports at module load

    alert = json.loads(body)
    is_duplicate, incident_id = evaluate_semantic_incident(alert)

    if is_duplicate:
        r_client.incr("metric:clustered_events")
        print(f"[Semantic Match] {alert.get('alert_id')} → {incident_id}")
    else:
        print(f"[New Threat Vector] Dispatching LangGraph workflow for {incident_id}")
        celery_app.send_task("tasks.process_security_graph", args=[alert])

        # Fast-path containment for confirmed brute-force before VT lookup
        if _BRUTE_FORCE_SIGNAL in alert.get("raw_log", "").lower():
            execute_active_response(alert["source_ip"])

    ch.basic_ack(delivery_tag=method.delivery_tag)


def start_worker_node() -> None:
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=_RABBITMQ_HOST)
    )
    channel = connection.channel()
    channel.queue_declare(queue="soar_event_stream", durable=True)
    # prefetch_count=1: hold one unacked message per worker.
    # Without this, RabbitMQ front-loads the fastest worker, causing RAM spikes
    # from buffered embedding payloads and starving slower workers.
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(
        queue="soar_event_stream", on_message_callback=on_message_callback
    )
    print("[Online] Semantic deduplication worker polling soar_event_stream…")
    channel.start_consuming()


if __name__ == "__main__":
    start_worker_node()
