import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, logs } from "../services/api";
import useSocket from "../hooks/useSocket";

const formatDateTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const normalizeStatus = (value) => {
  const normalized = String(value || "unknown").toLowerCase();
  if (normalized === "ok" || normalized === "healthy") return "online";
  return normalized;
};

const resolveLogPayload = (payload) => {
  if (!payload) return null;
  if (payload.data?._id) return payload.data;
  if (payload.log?._id) return payload.log;
  if (payload.latestEvent?._id) return payload.latestEvent;
  if (payload.items?.[0]?._id) return payload.items[0];
  if (payload.data?.items?.[0]?._id) return payload.data.items[0];
  return payload?._id ? payload : null;
};

const resolveAlertPayload = (payload) => {
  if (!payload) return null;
  if (payload.data?._id) return payload.data;
  if (payload.alert?._id) return payload.alert;
  return payload?._id ? payload : null;
};

const getLogSource = (log) =>
  log?.metadata?.sensorType || log?.source || "agent";

const getLogProtocol = (log) =>
  log?.metadata?.protocol ||
  log?.metadata?.appProtocol ||
  log?.metadata?.snort?.protocol ||
  "host";

const LiveMonitoring = () => {
  const [health, setHealth] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [collectorHeartbeat, setCollectorHeartbeat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [monitoring, setMonitoring] = useState(true);
  const [uptime, setUptime] = useState(0);
  const [consoleLines, setConsoleLines] = useState([]);
  const [error, setError] = useState("");

  const token = localStorage.getItem("accessToken");
  const isMountedRef = useRef(true);
  const refreshTimerRef = useRef(null);
  const uptimeRef = useRef(null);

  const pushConsoleLine = useCallback((line) => {
    setConsoleLines((current) =>
      [`[${new Date().toLocaleTimeString()}] ${line}`, ...current].slice(0, 80)
    );
  }, []);

  const fetchMonitoring = useCallback(async (silent = false) => {
    try {
      if (!silent) setLoading(true);
      setError("");

      const [healthResponse, logsResponse, alertsResponse] = await Promise.all([
        dashboard.health(),
        logs.list(30, 1),
        alerts.list(20, 1),
      ]);

      if (!isMountedRef.current) return;

      setHealth(healthResponse?.data ?? {});
      setRecentLogs(logsResponse?.data?.data ?? []);
      setRecentAlerts(alertsResponse?.data?.data ?? []);
      setCollectorHeartbeat(healthResponse?.data?.collector ?? null);
    } catch (fetchError) {
      console.error("Live monitoring error:", fetchError);
      if (isMountedRef.current) {
        setError(fetchError?.response?.data?.message || "Failed to load live monitoring.");
      }
    } finally {
      if (isMountedRef.current) setLoading(false);
    }
  }, []);

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => fetchMonitoring(true), 400);
  }, [fetchMonitoring]);

  const addIncomingLog = useCallback(
    (incoming) => {
      if (!incoming?._id) {
        scheduleRefresh();
        return;
      }

      setRecentLogs((current) => {
        const exists = current.some((item) => item._id === incoming._id);
        if (exists) {
          return current.map((item) =>
            item._id === incoming._id ? { ...item, ...incoming } : item
          );
        }
        return [incoming, ...current].slice(0, 30);
      });

      pushConsoleLine(
        `LOG: ${incoming.message || incoming.eventType || "Telemetry event"} | ${getLogSource(
          incoming
        )} | ${getLogProtocol(incoming)}`
      );
    },
    [pushConsoleLine, scheduleRefresh]
  );

  const addIncomingAlert = useCallback(
    (incoming) => {
      if (!incoming?._id) {
        scheduleRefresh();
        return;
      }

      setRecentAlerts((current) => {
        const exists = current.some((item) => item._id === incoming._id);
        if (exists) {
          return current.map((item) =>
            item._id === incoming._id ? { ...item, ...incoming } : item
          );
        }
        return [incoming, ...current].slice(0, 20);
      });

      pushConsoleLine(
        `ALERT: ${incoming.type || incoming.attackType || incoming.title || "Threat detected"} | ${
          incoming.severity || "unknown"
        }`
      );
    },
    [pushConsoleLine, scheduleRefresh]
  );

  const socketHandlers = useMemo(
    () => ({
      "logs:new": (payload) => addIncomingLog(resolveLogPayload(payload)),
      "log:new": (payload) => addIncomingLog(resolveLogPayload(payload)),
      "alerts:new": (payload) => addIncomingAlert(resolveAlertPayload(payload)),
      "alert:new": (payload) => addIncomingAlert(resolveAlertPayload(payload)),
      "alerts:update": scheduleRefresh,
      "dashboard:update": scheduleRefresh,
      "health:update": scheduleRefresh,
      "collector:heartbeat": (payload) => {
        const heartbeat = payload?.data || payload;
        setCollectorHeartbeat(heartbeat);
        pushConsoleLine(`HEARTBEAT: ${heartbeat?.hostname || heartbeat?.assetId || "agent"}`);
        scheduleRefresh();
      },
    }),
    [addIncomingAlert, addIncomingLog, pushConsoleLine, scheduleRefresh]
  );

  const socketState = useSocket(token, socketHandlers);

  useEffect(() => {
    isMountedRef.current = true;
    fetchMonitoring();

    uptimeRef.current = setInterval(() => {
      if (monitoring) setUptime((current) => current + 1);
    }, 1000);

    return () => {
      isMountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
      clearInterval(uptimeRef.current);
    };
  }, [fetchMonitoring, monitoring]);

  const startMonitoring = () => {
    setMonitoring(true);
    pushConsoleLine("Monitoring started. Listening for live HIDS/NIDS events.");
    fetchMonitoring(true);
  };

  const stopMonitoring = () => {
    setMonitoring(false);
    pushConsoleLine("Monitoring paused on frontend. Agent/backend may still be running.");
  };

  const formatUptime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  };

  const statusCards = useMemo(
    () => [
      {
        label: "HIDS Agent",
        value: normalizeStatus(collectorHeartbeat?.status || health?.host?.status),
        meta:
          collectorHeartbeat?.hostname ||
          collectorHeartbeat?.agentType ||
          "Waiting for endpoint telemetry",
      },
      {
        label: "NIDS / Snort",
        value: normalizeStatus(health?.snort?.status || "disabled"),
        meta: health?.snort?.lastEventAt
          ? `Last event ${formatDateTime(health.snort.lastEventAt)}`
          : "Disabled on Windows demo",
      },
      {
        label: "IDS Engine",
        value: normalizeStatus(health?.idsEngine?.status),
        meta: health?.idsEngine?.message || "ML / rule detection service",
      },
      {
        label: "Socket.io",
        value: socketState.connectionStatus,
        meta: socketState.lastError || "Live event channel",
      },
    ],
    [collectorHeartbeat, health, socketState]
  );

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading live monitoring...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <style>{`
        .monitor-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background: linear-gradient(135deg, #fff7ed 0%, #f8fbff 55%, #eef9f1 100%);
        }
        .monitor-shell { max-width: 1180px; margin: 0 auto; }
        .monitor-hero {
          background: linear-gradient(135deg, rgba(255,255,255,.96), rgba(240,253,244,.88));
          border-radius: 22px;
          padding: 34px;
          box-shadow: 0 18px 45px rgba(15,23,42,.08);
          border: 1px solid rgba(148,163,184,.18);
          margin-bottom: 24px;
        }
        .monitor-hero h1 { margin: 0; font-size: 34px; color: #0f2742; }
        .monitor-hero p { margin: 14px 0 16px; color: #64748b; font-size: 15px; }
        .monitor-badges { display: flex; gap: 12px; flex-wrap: wrap; }
        .monitor-badges span {
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
          color: white;
          padding: 9px 16px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 900;
        }
        .monitor-stats {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 20px;
          margin-bottom: 24px;
        }
        .monitor-stat-card {
          background: rgba(255,255,255,.96);
          border-radius: 18px;
          padding: 26px;
          text-align: center;
          border: 1px solid rgba(148,163,184,.18);
          box-shadow: 0 14px 34px rgba(15,23,42,.07);
        }
        .monitor-stat-card strong {
          display: block;
          font-size: 34px;
          color: #0ea5e9;
          margin-bottom: 8px;
        }
        .monitor-stat-card:nth-child(2) strong { color: #ef4444; }
        .monitor-stat-card:nth-child(3) strong { color: #059669; }
        .monitor-stat-card span {
          color: #64748b;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: .08em;
        }
        .monitor-grid {
          display: grid;
          grid-template-columns: minmax(0, 2fr) minmax(300px, .9fr);
          gap: 24px;
          align-items: start;
        }
        .monitor-card {
          background: rgba(255,255,255,.96);
          border-radius: 20px;
          border: 1px solid rgba(148,163,184,.18);
          box-shadow: 0 16px 40px rgba(15,23,42,.08);
          overflow: hidden;
        }
        .monitor-card-header {
          padding: 22px 26px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 18px;
          border-bottom: 1px solid #eef2f7;
        }
        .live-dot {
          width: 14px;
          height: 14px;
          border-radius: 999px;
          background: ${monitoring ? "#22c55e" : "#ef4444"};
          box-shadow: 0 0 0 6px ${
            monitoring ? "rgba(34,197,94,.13)" : "rgba(239,68,68,.12)"
          };
        }
        .monitor-card-header h3 { margin: 0; color: #172033; }
        .monitor-card-header p { margin: 6px 0 0; color: #64748b; font-size: 14px; }
        .monitor-actions { display: flex; gap: 12px; flex-wrap: wrap; }
        .start-btn,.stop-btn {
          border: 0;
          border-radius: 12px;
          padding: 13px 22px;
          font-weight: 900;
          cursor: pointer;
          color: #fff;
        }
        .start-btn { background: linear-gradient(90deg, #0ea5e9, #2563eb); }
        .stop-btn { background: linear-gradient(90deg, #fb7185, #ef4444); }
        .terminal-box {
          margin: 26px;
          min-height: 360px;
          max-height: 420px;
          background: radial-gradient(circle at top, #101c31, #060b14);
          border-radius: 18px;
          padding: 22px;
          color: #dbeafe;
          font-family: Consolas, monospace;
          overflow: auto;
        }
        .terminal-line {
          padding: 8px 0;
          border-bottom: 1px solid rgba(255,255,255,.06);
          font-size: 13px;
          white-space: pre-wrap;
        }
        .terminal-line strong { color: #38bdf8; }
        .terminal-placeholder {
          height: 300px;
          display: grid;
          place-items: center;
          text-align: center;
          color: #64748b;
        }
        .monitor-footer {
          padding: 14px 26px 24px;
          display: flex;
          justify-content: space-between;
          gap: 12px;
          color: #64748b;
          font-size: 13px;
          flex-wrap: wrap;
        }
        .side-section { padding: 24px; }
        .overview-box {
          margin-top: 18px;
          background: #f8fbff;
          border-radius: 16px;
          padding: 18px;
          border: 1px solid #e2e8f0;
        }
        .overview-box h4 { margin: 0 0 8px; color: #172033; }
        .overview-box p { margin: 0 0 14px; color: #64748b; line-height: 1.6; }
        .health-list { display: grid; gap: 12px; margin-top: 18px; }
        .health-row {
          border-left: 4px solid #0ea5e9;
          background: #f8fbff;
          border-radius: 12px;
          padding: 14px;
        }
        .health-row strong {
          display: flex;
          justify-content: space-between;
          color: #172033;
          margin-bottom: 6px;
          gap: 8px;
        }
        .health-row small { color: #64748b; }
        .error-message {
          background: #fff1f2;
          color: #be123c;
          border: 1px solid #fecdd3;
          border-radius: 12px;
          padding: 14px 16px;
          margin-bottom: 18px;
          font-weight: 800;
        }
        @media (max-width: 980px) {
          .monitor-page { padding: 22px; }
          .monitor-stats, .monitor-grid { grid-template-columns: 1fr; }
        }
      `}</style>

      <div className="monitor-page">
        <div className="monitor-shell">
          <section className="monitor-hero">
            <h1>〽️ Live Network Monitoring</h1>
            <p>
              Real-time HIDS agent telemetry, backend ingestion, live socket updates,
              and IDS detection visibility.
            </p>
            <div className="monitor-badges">
              <span>HIDS Agent Active</span>
              <span>MongoDB Ingest</span>
              <span>Socket.io Live</span>
            </div>
          </section>

          {error && <div className="error-message">{error}</div>}

          <section className="monitor-stats">
            <div className="monitor-stat-card">
              <strong>{recentLogs.length}</strong>
              <span>Events Observed</span>
            </div>
            <div className="monitor-stat-card">
              <strong>{recentAlerts.length}</strong>
              <span>Threat Alerts</span>
            </div>
            <div className="monitor-stat-card">
              <strong>{formatUptime(uptime)}</strong>
              <span>Frontend Monitor Uptime</span>
            </div>
          </section>

          <section className="monitor-grid">
            <div className="monitor-card">
              <div className="monitor-card-header">
                <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
                  <div className="live-dot" />
                  <div>
                    <h3>Live telemetry stream</h3>
                    <p>Real HIDS/NIDS events from backend APIs and sockets</p>
                  </div>
                </div>

                <div className="monitor-actions">
                  <button className="start-btn" type="button" onClick={startMonitoring}>
                    ▶ Start Monitoring
                  </button>
                  <button className="stop-btn" type="button" onClick={stopMonitoring}>
                    ■ Stop
                  </button>
                </div>
              </div>

              <div className="terminal-box">
                {consoleLines.length || recentLogs.length ? (
                  <>
                    {consoleLines.map((line, index) => (
                      <div className="terminal-line" key={`line-${index}`}>
                        {line}
                      </div>
                    ))}

                    {recentLogs.slice(0, 12).map((log, index) => (
                      <div className="terminal-line" key={log._id || index}>
                        <strong>[{formatDateTime(log.timestamp || log.createdAt)}]</strong>{" "}
                        {log.message || log.eventType || "Telemetry Event"} |{" "}
                        {getLogSource(log)} | {getLogProtocol(log)}
                      </div>
                    ))}
                  </>
                ) : (
                  <div className="terminal-placeholder">
                    <section>
                      <div>▻_</div>
                      <p>Monitoring Console Ready</p>
                      <p>Waiting for HIDS agent telemetry...</p>
                    </section>
                  </div>
                )}
              </div>

              <div className="monitor-footer">
                <span>Live source: agent → api-server → MongoDB → frontend</span>
                <span>
                  Last event:{" "}
                  {recentLogs[0]?.timestamp
                    ? new Date(recentLogs[0].timestamp).toLocaleTimeString()
                    : "—"}
                </span>
              </div>
            </div>

            <aside className="monitor-card">
              <div className="monitor-card-header">
                <div>
                  <h3>System health</h3>
                  <p>Current live monitoring components</p>
                </div>
              </div>

              <div className="side-section">
                <div className="overview-box">
                  <h4>Current Working Proof</h4>
                  <p>
                    The HIDS agent is connected, heartbeats are accepted, and logs are
                    being inserted into MongoDB through the backend.
                  </p>

                  <h4>Alert Note</h4>
                  <p>
                    Alerts appear only when suspicious traffic or rule-triggering events
                    are generated.
                  </p>
                </div>

                <div className="health-list">
                  {statusCards.map((card) => (
                    <div key={card.label} className="health-row">
                      <strong>
                        {card.label}
                        <span>{card.value}</span>
                      </strong>
                      <small>{card.meta}</small>
                    </div>
                  ))}
                </div>
              </div>
            </aside>
          </section>
        </div>
      </div>
    </MainLayout>
  );
};

export default LiveMonitoring;