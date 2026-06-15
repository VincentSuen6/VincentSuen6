"use client";

import { useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PendingAlert {
  source_ip:    string;
  target_host:  string;
  alert_type:   string;
  threat_score: number;
  mitre:        string[];
  raw_log:      string;
}

interface SSEPayload {
  info_count:          number;
  warning_count:       number;
  error_count:         number;
  total_contained:     number;
  pending_count:       number;
  detection_threshold: number;
  pipeline_status:     string;
  pending_approvals:   Record<string, string>;  // thread_id → JSON string
}

const SOAR_API = process.env.NEXT_PUBLIC_SOAR_API_URL ?? "http://localhost:8000";
const API_KEY  = process.env.NEXT_PUBLIC_SOAR_API_KEY ?? "";

// ---------------------------------------------------------------------------
// Metric card
// ---------------------------------------------------------------------------

function MetricCard({
  label,
  value,
  color,
  sub,
}: {
  label: string;
  value: string | number;
  color: string;
  sub?: string;
}) {
  return (
    <div style={{
      border: `1px solid ${color}44`,
      borderRadius: 6,
      padding: "16px 20px",
      background: "#161b22",
      minWidth: 160,
      flex: "1 1 160px",
    }}>
      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 1, textTransform: "uppercase" }}>
        {label}
      </div>
      <div style={{ fontSize: 32, fontWeight: 700, color, marginTop: 4 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: "#8b949e", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// HITL card
// ---------------------------------------------------------------------------

function HITLCard({
  threadId,
  alert,
  onDecision,
}: {
  threadId: string;
  alert: PendingAlert;
  onDecision: (threadId: string, approved: boolean) => void;
}) {
  const scoreColor =
    alert.threat_score >= 9  ? "#f85149" :
    alert.threat_score >= 7  ? "#e3b341" :
    alert.threat_score >= 4  ? "#d29922" : "#3fb950";

  return (
    <div style={{
      border: "1px solid #30363d",
      borderRadius: 6,
      padding: 16,
      background: "#161b22",
      marginBottom: 12,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <span style={{
            fontSize: 11,
            background: "#f8514922",
            color: "#f85149",
            border: "1px solid #f8514944",
            borderRadius: 4,
            padding: "2px 8px",
            marginRight: 8,
          }}>
            PENDING APPROVAL
          </span>
          <span style={{ fontWeight: 700, fontSize: 15 }}>{alert.alert_type}</span>
        </div>
        <span style={{
          fontSize: 22,
          fontWeight: 700,
          color: scoreColor,
          background: `${scoreColor}18`,
          border: `1px solid ${scoreColor}44`,
          borderRadius: 6,
          padding: "2px 12px",
        }}>
          {alert.threat_score.toFixed(1)}/10
        </span>
      </div>

      <table style={{ marginTop: 12, fontSize: 12, borderCollapse: "collapse", width: "100%" }}>
        <tbody>
          {[
            ["Source IP",   alert.source_ip],
            ["Target Host", alert.target_host],
            ["MITRE",       alert.mitre?.join(", ") || "—"],
            ["Thread",      threadId],
          ].map(([k, v]) => (
            <tr key={k}>
              <td style={{ color: "#8b949e", paddingRight: 16, paddingBottom: 4, whiteSpace: "nowrap" }}>{k}</td>
              <td style={{ color: "#c9d1d9", wordBreak: "break-all" }}>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {alert.raw_log && (
        <pre style={{
          marginTop: 10,
          padding: "8px 12px",
          background: "#0d1117",
          border: "1px solid #30363d",
          borderRadius: 4,
          fontSize: 11,
          color: "#8b949e",
          overflowX: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          maxHeight: 80,
          overflow: "auto",
        }}>
          {alert.raw_log}
        </pre>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
        <button
          onClick={() => onDecision(threadId, true)}
          style={{
            flex: 1,
            padding: "8px 0",
            background: "#238636",
            border: "1px solid #2ea04344",
            borderRadius: 6,
            color: "#fff",
            cursor: "pointer",
            fontFamily: "inherit",
            fontWeight: 700,
            fontSize: 13,
            letterSpacing: 0.5,
          }}
        >
          APPROVE — Block IP
        </button>
        <button
          onClick={() => onDecision(threadId, false)}
          style={{
            flex: 1,
            padding: "8px 0",
            background: "#21262d",
            border: "1px solid #f8514944",
            borderRadius: 6,
            color: "#f85149",
            cursor: "pointer",
            fontFamily: "inherit",
            fontWeight: 700,
            fontSize: 13,
            letterSpacing: 0.5,
          }}
        >
          DENY — False Positive
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Log line
// ---------------------------------------------------------------------------

function LogLine({ msg, ts }: { msg: string; ts: string }) {
  const color =
    msg.includes("APPROVE") ? "#3fb950" :
    msg.includes("DENY")    ? "#f85149" :
    msg.includes("ERROR")   ? "#e3b341" : "#8b949e";

  return (
    <div style={{ fontSize: 11, color, marginBottom: 2 }}>
      <span style={{ color: "#484f58" }}>{ts} </span>{msg}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function Dashboard() {
  const [metrics, setMetrics]     = useState<Omit<SSEPayload, "pending_approvals"> | null>(null);
  const [pending, setPending]     = useState<Record<string, PendingAlert>>({});
  const [log, setLog]             = useState<Array<{ msg: string; ts: string }>>([]);
  const [status, setStatus]       = useState<"connecting" | "live" | "disconnected">("connecting");
  const [deciding, setDeciding]   = useState<Set<string>>(new Set());
  const eventSourceRef            = useRef<EventSource | null>(null);

  const addLog = (msg: string) => {
    const ts = new Date().toLocaleTimeString();
    setLog(prev => [{ msg, ts }, ...prev].slice(0, 100));
  };

  // SSE connection
  useEffect(() => {
    const connect = () => {
      const es = new EventSource(`${SOAR_API}/api/events`);
      eventSourceRef.current = es;

      es.onopen = () => {
        setStatus("live");
        addLog("SSE stream connected.");
      };

      es.onmessage = (e) => {
        try {
          const data: SSEPayload = JSON.parse(e.data);
          const { pending_approvals, ...rest } = data;
          setMetrics(rest);

          // Parse each pending approval from its JSON string
          const parsed: Record<string, PendingAlert> = {};
          for (const [tid, raw] of Object.entries(pending_approvals || {})) {
            try { parsed[tid] = JSON.parse(raw as string); } catch {}
          }
          setPending(parsed);
        } catch {}
      };

      es.onerror = () => {
        setStatus("disconnected");
        addLog("SSE disconnected — reconnecting in 5 s...");
        es.close();
        setTimeout(connect, 5000);
      };
    };

    connect();
    return () => eventSourceRef.current?.close();
  }, []);

  const decide = async (threadId: string, approved: boolean) => {
    setDeciding(prev => new Set(prev).add(threadId));
    const endpoint = approved ? "approve" : "deny";
    try {
      const res = await fetch(`${SOAR_API}/api/v1/${endpoint}/${threadId}`, {
        method: "POST",
        headers: { "X-API-Key": API_KEY },
      });
      if (res.ok) {
        addLog(`${approved ? "APPROVED" : "DENIED"} thread ${threadId}`);
        setPending(prev => {
          const next = { ...prev };
          delete next[threadId];
          return next;
        });
      } else {
        addLog(`ERROR: ${endpoint} returned ${res.status} for ${threadId}`);
      }
    } catch (err) {
      addLog(`ERROR: network failure on ${endpoint} — ${err}`);
    } finally {
      setDeciding(prev => {
        const next = new Set(prev);
        next.delete(threadId);
        return next;
      });
    }
  };

  const pendingEntries = Object.entries(pending);

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "24px 16px" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
        <div style={{
          width: 10, height: 10, borderRadius: "50%",
          background: status === "live" ? "#3fb950" : status === "connecting" ? "#e3b341" : "#f85149",
          boxShadow: `0 0 8px ${status === "live" ? "#3fb950" : "#f85149"}`,
        }} />
        <h1 style={{ fontSize: 18, fontWeight: 700, color: "#e6edf3", letterSpacing: 0.5 }}>
          SOC OPERATOR — AUTONOMOUS SOAR ENGINE
        </h1>
        <span style={{ marginLeft: "auto", fontSize: 11, color: "#484f58", textTransform: "uppercase" }}>
          {status === "live" ? "LIVE" : status === "connecting" ? "CONNECTING..." : "RECONNECTING..."}
        </span>
      </div>

      {/* Metrics row */}
      {metrics && (
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
          <MetricCard label="Info / Filtered"    value={metrics.info_count}          color="#58a6ff" />
          <MetricCard label="Warnings Queued"    value={metrics.warning_count}        color="#e3b341" />
          <MetricCard label="Errors"             value={metrics.error_count}          color="#f85149" />
          <MetricCard label="IPs Blocked"        value={metrics.total_contained}      color="#3fb950" />
          <MetricCard
            label="Detection Threshold"
            value={metrics.detection_threshold.toFixed(1)}
            color="#d2a8ff"
            sub="Adaptive · max 9.5"
          />
          <MetricCard
            label="Pipeline"
            value={metrics.pipeline_status}
            color="#3fb950"
          />
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 16 }}>

        {/* HITL queue */}
        <div>
          <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 10, letterSpacing: 1, textTransform: "uppercase" }}>
            Pending Approval — {pendingEntries.length} alert{pendingEntries.length !== 1 ? "s" : ""}
          </div>

          {pendingEntries.length === 0 ? (
            <div style={{
              border: "1px dashed #30363d",
              borderRadius: 6,
              padding: 32,
              textAlign: "center",
              color: "#484f58",
              fontSize: 13,
            }}>
              No alerts awaiting approval.
            </div>
          ) : (
            pendingEntries.map(([threadId, alert]) => (
              <div key={threadId} style={{ opacity: deciding.has(threadId) ? 0.5 : 1, transition: "opacity 0.2s" }}>
                <HITLCard
                  threadId={threadId}
                  alert={alert}
                  onDecision={decide}
                />
              </div>
            ))
          )}
        </div>

        {/* Audit log */}
        <div>
          <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 10, letterSpacing: 1, textTransform: "uppercase" }}>
            Operator Log
          </div>
          <div style={{
            border: "1px solid #30363d",
            borderRadius: 6,
            padding: 12,
            background: "#0d1117",
            height: 500,
            overflowY: "auto",
          }}>
            {log.length === 0
              ? <span style={{ color: "#484f58", fontSize: 11 }}>Waiting for events…</span>
              : log.map((entry, i) => <LogLine key={i} msg={entry.msg} ts={entry.ts} />)
            }
          </div>

          {/* Quick links */}
          <div style={{ marginTop: 16, fontSize: 11, color: "#484f58" }}>
            <div style={{ marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Quick links</div>
            {[
              ["Jaeger traces",   "http://localhost:16686"],
              ["RabbitMQ mgmt",   "http://localhost:15672"],
              ["Qdrant dashboard","http://localhost:6334/dashboard"],
              ["Prometheus",      "http://localhost:8000/metrics"],
              ["STIX IOC export", "http://localhost:8000/api/v1/iocs/stix"],
            ].map(([label, url]) => (
              <div key={label} style={{ marginBottom: 3 }}>
                <a href={url} target="_blank" rel="noreferrer">{label}</a>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
