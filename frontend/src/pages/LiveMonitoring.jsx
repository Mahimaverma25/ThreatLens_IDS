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
  return normalized === "ok" ? "online" : normalized;
};

const resolveLogPayload = (payload) => payload?.data || payload;
const resolveAlertPayload = (payload) => payload?.data || payload;

const LiveMonitoring = () => {
  const [health, setHealth] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [collectorHeartbeat, setCollectorHeartbeat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const token = localStorage.getItem("accessToken");
  const isMountedRef = useRef(true);
  const refreshTimerRef = useRef(null);

  const fetchMonitoring = useCallback(async (silent = false) => {
    try {
      if (silent) setRefreshing(true);
      else setLoading(true);

      setError("");

      const [healthResponse, logsResponse, alertsResponse] = await Promise.all([
        dashboard.health(),
        logs.list(20, 1),
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
      if (isMountedRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => fetchMonitoring(true), 300);
  }, [fetchMonitoring]);

  const socketHandlers = useMemo(
    () => ({
      "logs:new": (payload) => {
        const incoming = resolveLogPayload(payload);
        setRecentLogs((current) => [incoming, ...current].slice(0, 20));
      },
      "alerts:new": (payload) => {
        const incoming = resolveAlertPayload(payload);
        setRecentAlerts((current) => [incoming, ...current].slice(0, 20));
      },
      "alerts:update": scheduleRefresh,
      "collector:heartbeat": (payload) => {
        const heartbeat = payload?.data || payload;
        setCollectorHeartbeat(heartbeat);
        scheduleRefresh();
      },
      "health:update": scheduleRefresh,
    }),
    [scheduleRefresh]
  );

  const socketState = useSocket(token, socketHandlers);

  useEffect(() => {
    isMountedRef.current = true;
    fetchMonitoring();

    return () => {
      isMountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
    };
  }, [fetchMonitoring]);

  const statusCards = useMemo(
    () => [
      {
        label: "NIDS Status",
        value: normalizeStatus(health?.snort?.status),
        meta: health?.snort?.lastEventAt ? `Last event ${formatDateTime(health.snort.lastEventAt)}` : "Waiting for network telemetry",
      },
      {
        label: "HIDS Status",
        value: normalizeStatus(health?.host?.status),
        meta: health?.host?.lastEventAt ? `Last event ${formatDateTime(health.host.lastEventAt)}` : "Waiting for endpoint telemetry",
      },
      {
        label: "IDS Engine",
        value: normalizeStatus(health?.idsEngine?.status),
        meta: health?.idsEngine?.message || "Model runtime health",
      },
      {
        label: "Collector",
        value: normalizeStatus(collectorHeartbeat?.status),
        meta: collectorHeartbeat?.hostname || collectorHeartbeat?.agentType || "No collector heartbeat",
      },
    ],
    [collectorHeartbeat, health]
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
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Live monitoring / real-time telemetry</div>
          <h1>Live Monitoring</h1>
          <p>
            Watch live logs, live alerts, and the current runtime health of NIDS, HIDS,
            and the IDS engine from one operational console.
          </p>
        </div>
        <div className="command-actions">
          <button type="button" className="secondary-btn" onClick={() => fetchMonitoring(true)} disabled={refreshing}>
            {refreshing ? "Refreshing..." : "Refresh Live View"}
          </button>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Socket.io</span>
          <strong>{socketState.connectionStatus}</strong>
          <small>{socketState.lastError || "Live channel active"}</small>
        </div>
        {statusCards.map((card) => (
          <div key={card.label} className="metric-card metric-card--subtle">
            <span>{card.label}</span>
            <strong>{card.value}</strong>
            <small>{card.meta}</small>
          </div>
        ))}
      </section>

      <section className="dashboard-grid dashboard-grid--premium">
        <div className="dashboard-panel panel-span-2">
          <div className="panel-header">
            <h3>Live Logs</h3>
            <span>Socket-driven telemetry updates</span>
          </div>
          {recentLogs.length ? (
            <div className="panel-table">
              <table>
                <thead>
                  <tr>
                    <th>Message</th>
                    <th>Source</th>
                    <th>Protocol</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {recentLogs.slice(0, 10).map((log, index) => (
                    <tr key={log._id || index}>
                      <td>{log.message || log.eventType || "Telemetry Event"}</td>
                      <td>{log.source || log.metadata?.sensorType || "-"}</td>
                      <td>{log.metadata?.protocol || log.metadata?.appProtocol || log.metadata?.snort?.protocol || "-"}</td>
                      <td>{formatDateTime(log.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <h3>No live logs yet</h3>
              <p>Logs received over Socket.io will stream here.</p>
            </div>
          )}
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>System Health</h3>
            <span>Realtime service checks</span>
          </div>
          <div className="panel-list">
            {statusCards.map((card) => (
              <div key={card.label} className="list-row list-row-stack">
                <div className="list-row__top">
                  <strong>{card.label}</strong>
                  <span>{card.value}</span>
                </div>
                <div className="list-meta">{card.meta}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-panel panel-span-3">
          <div className="panel-header">
            <h3>Live Alerts</h3>
            <span>Incoming detections and updates</span>
          </div>
          {recentAlerts.length ? (
            <div className="panel-table">
              <table>
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Source</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.slice(0, 10).map((alert, index) => (
                    <tr key={alert._id || index}>
                      <td>{alert.type || alert.attackType || "Alert"}</td>
                      <td>{alert.severity || "-"}</td>
                      <td>{alert.status || "New"}</td>
                      <td>{alert.source || "ThreatLens"}</td>
                      <td>{formatDateTime(alert.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <h3>No live alerts yet</h3>
              <p>Live alert events will appear here as they are emitted by the backend.</p>
            </div>
          )}
        </div>
      </section>
    </MainLayout>
  );
};

export default LiveMonitoring;
