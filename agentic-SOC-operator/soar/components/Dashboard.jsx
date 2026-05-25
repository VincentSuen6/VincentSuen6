import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, Terminal,
  Wifi, WifiOff, Clock, XCircle,
} from 'lucide-react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const LOG_COLORS = {
  INFO:  'text-emerald-500',
  WARN:  'text-amber-400',
  AUDIT: 'text-sky-400',
  ERROR: 'text-rose-400',
  HITL:  'text-purple-400',
};

// ---------------------------------------------------------------------------
// Dashboard root
// ---------------------------------------------------------------------------
export default function SOARDashboard() {
  const [metrics, setMetrics] = useState({
    info_count:          0,
    warning_count:       0,
    error_count:         0,
    total_contained:     0,
    pending_count:       0,
    detection_threshold: 7.5,
    pipeline_status:     'CONNECTING',
    pending_approvals:   {},
  });
  const [connected, setConnected] = useState(false);
  const [logs, setLogs] = useState([
    { ts: new Date().toISOString(), level: 'INFO', msg: 'Dashboard initializing…' },
  ]);
  const logsEndRef = useRef(null);

  const appendLog = useCallback((level, msg) => {
    setLogs(prev => [
      ...prev.slice(-199),   // circular buffer — keep last 200 entries
      { ts: new Date().toISOString(), level, msg },
    ]);
  }, []);

  // Auto-scroll log terminal
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // -----------------------------------------------------------------------
  // SSE connection — server pushes every 2 s, no client polling
  // -----------------------------------------------------------------------
  useEffect(() => {
    const es = new EventSource(`${API_BASE}/api/events`);

    es.onopen = () => {
      setConnected(true);
      appendLog('INFO', 'SSE stream connected to ingestion fabric.');
    };

    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      setMetrics(data);

      if (data.pending_count > 0) {
        appendLog('HITL', `${data.pending_count} action(s) awaiting human approval.`);
      }
    };

    es.onerror = () => {
      setConnected(false);
      appendLog('ERROR', 'SSE connection lost. Browser will reconnect automatically.');
    };

    return () => es.close();
  }, [appendLog]);

  // -----------------------------------------------------------------------
  // Simulate a brute-force attack from the UI
  // -----------------------------------------------------------------------
  const triggerMockAttack = async () => {
    const alertId = `ALT-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
    appendLog('WARN', `Simulating Hydra brute-force from 192.168.43.10 (${alertId})`);
    try {
      const res  = await fetch(`${API_BASE}/api/v1/ingest`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id:        alertId,
          vendor:          'Wazuh',
          alert_type:      'Brute Force',
          source_ip:       '192.168.43.10',
          target_host:     'PROD_SERVER_01',
          failed_attempts: 14,
          raw_log:         'Failed password for root from 192.168.43.10 port 22 ssh2',
        }),
      });
      const body = await res.json();
      appendLog('INFO', `Ingest: ${body.status}${body.task_id ? ` — task ${body.task_id}` : ''}`);
    } catch {
      appendLog('ERROR', 'Could not reach ingestion endpoint.');
    }
  };

  // -----------------------------------------------------------------------
  // HITL approve / deny
  // -----------------------------------------------------------------------
  const hitlAction = async (threadId, approved) => {
    const endpoint = approved ? 'approve' : 'deny';
    const label    = approved ? 'Approved' : 'Denied';
    try {
      await fetch(`${API_BASE}/api/v1/${endpoint}/${threadId}`, { method: 'POST' });
      appendLog('HITL', `${label} containment for thread ${threadId}`);
    } catch {
      appendLog('ERROR', `Failed to send ${endpoint} signal.`);
    }
  };

  // Parse raw {thread_id: json_string} dict from SSE into objects
  const pendingItems = Object.entries(metrics.pending_approvals ?? {}).map(
    ([threadId, raw]) => {
      try   { return { threadId, ...JSON.parse(raw) }; }
      catch { return null; }
    }
  ).filter(Boolean);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------
  return (
    <div className="p-8 bg-zinc-950 text-zinc-100 min-h-screen font-sans">

      {/* Header */}
      <div className="flex justify-between items-center mb-8 border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-3">
          <Shield className="text-emerald-400" size={24} />
          <h1 className="text-2xl font-bold tracking-tight text-emerald-400">
            SOC OPERATOR // AUTONOMOUS IR FRAMEWORK
          </h1>
          <span className={`flex items-center gap-1 text-xs px-2 py-1 rounded-full font-medium ${
            connected ? 'bg-emerald-900 text-emerald-300' : 'bg-zinc-800 text-zinc-400'
          }`}>
            {connected ? <Wifi size={10} /> : <WifiOff size={10} />}
            {connected ? 'LIVE' : 'RECONNECTING'}
          </span>
        </div>
        <button
          onClick={triggerMockAttack}
          className="bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white font-medium px-4 py-2 rounded transition-colors text-sm"
        >
          Simulate Hydra Brute-Force Attack
        </button>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        <MetricCard title="Filtered / Deduped"  count={metrics.info_count}      color="text-zinc-400" />
        <MetricCard title="Triaged Alerts"       count={metrics.warning_count}   color="text-amber-400"   icon={<AlertTriangle size={18} />} />
        <MetricCard title="System Errors"        count={metrics.error_count}     color="text-rose-500" />
        <MetricCard title="Containments"         count={metrics.total_contained} color="text-emerald-400" icon={<CheckCircle size={18} />} />
        <MetricCard
          title="Awaiting Approval"
          count={metrics.pending_count}
          color={metrics.pending_count > 0 ? 'text-purple-400 animate-pulse' : 'text-zinc-400'}
          icon={<Clock size={18} />}
        />
        <MetricCard
          title="Detect Threshold"
          count={metrics.detection_threshold?.toFixed(1) ?? '7.5'}
          color="text-sky-400"
          raw
        />
      </div>

      {/* Human-in-the-Loop approval panel */}
      {pendingItems.length > 0 && (
        <div className="mb-8 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-purple-400 flex items-center gap-2">
            <Clock size={16} /> Human Approval Required
          </h2>
          {pendingItems.map((item) => (
            <div
              key={item.threadId}
              className="bg-purple-950/30 border border-purple-600 rounded p-4 flex flex-col md:flex-row md:items-center gap-4"
            >
              <div className="flex-1 space-y-1">
                <p className="text-sm font-mono text-purple-200">
                  Block <span className="text-white font-bold">{item.source_ip}</span>
                  {' '}targeting <span className="text-white font-bold">{item.target_host}</span>
                </p>
                <p className="text-xs text-zinc-400">
                  Threat Score: <span className="text-amber-400">{item.threat_score?.toFixed(1)}</span>
                  {' '}| Type: <span className="text-zinc-300">{item.alert_type}</span>
                  {' '}| Thread: <span className="font-mono text-zinc-500">{item.threadId}</span>
                </p>
                {item.mitre?.length > 0 && (
                  <p className="text-xs text-sky-400 font-mono">{item.mitre.join(' · ')}</p>
                )}
              </div>
              <div className="flex gap-3 shrink-0">
                <button
                  onClick={() => hitlAction(item.threadId, true)}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded text-sm transition-colors flex items-center gap-1"
                >
                  <CheckCircle size={14} /> Approve Block
                </button>
                <button
                  onClick={() => hitlAction(item.threadId, false)}
                  className="bg-zinc-700 hover:bg-zinc-600 text-zinc-200 font-medium px-4 py-2 rounded text-sm transition-colors flex items-center gap-1"
                >
                  <XCircle size={14} /> Deny
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Audit terminal */}
      <div className="bg-zinc-900 border border-zinc-800 rounded p-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
          <Terminal size={16} /> Pipeline Audit Trail
        </h2>
        <div className="bg-black p-4 rounded font-mono text-xs h-56 overflow-y-auto border border-zinc-800 space-y-1">
          {logs.map((entry, i) => (
            <p key={i} className={LOG_COLORS[entry.level] ?? 'text-zinc-400'}>
              <span className="text-zinc-600">[{entry.ts.slice(11, 19)}]</span>{' '}
              <span className="text-zinc-500">[{entry.level}]</span>{' '}
              {entry.msg}
            </p>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MetricCard
// ---------------------------------------------------------------------------
function MetricCard({ title, count, color, icon, raw }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 p-5 rounded flex justify-between items-center">
      <div>
        <p className="text-xs font-medium uppercase tracking-wider text-zinc-400">{title}</p>
        {/* tabular-nums prevents layout shift as counter digits change width */}
        <p className={`text-3xl font-bold mt-1 tabular-nums ${color}`}>
          {raw ? count : (typeof count === 'number' ? count.toLocaleString() : count)}
        </p>
      </div>
      {icon && <div className={color}>{icon}</div>}
    </div>
  );
}
