import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { reports } from "../services/api";
import { useAuth } from "../context/AuthContext";
import useSocket from "../hooks/useSocket";

const downloadBlob = (filename, blob) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.setAttribute("download", filename);
  document.body.appendChild(link);
  link.click();

  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

const formatDate = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const normalizeSeverity = (severity = "") => String(severity).toLowerCase();

const Reports = () => {
  const { user } = useAuth();

  const [alertList, setAlertList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [exporting, setExporting] = useState("");
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const isAdmin = user?.role === "admin";
  const token = localStorage.getItem("accessToken");
  const mountedRef = useRef(true);
  const refreshTimerRef = useRef(null);

  const fetchReports = useCallback(async (silent = false) => {
    try {
      if (silent) setRefreshing(true);
      else setLoading(true);

      setError("");

      const response = await reports.summary();
      const data = response?.data?.data || {};

      if (!mountedRef.current) return;

      setAlertList(Array.isArray(data.alerts) ? data.alerts : []);
      setLogList(Array.isArray(data.logs) ? data.logs : []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Reports fetch error:", err);

      if (mountedRef.current) {
        setError(
          err?.response?.data?.message ||
            "Failed to load reporting data. Please check backend connection."
        );
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => fetchReports(true), 500);
  }, [fetchReports]);

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": scheduleRefresh,
      "alerts:update": scheduleRefresh,
      "logs:new": scheduleRefresh,
      "collector:heartbeat": scheduleRefresh,
    }),
    [scheduleRefresh]
  );

  const socketState = useSocket(token, socketHandlers);

  useEffect(() => {
    mountedRef.current = true;
    fetchReports();

    return () => {
      mountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
    };
  }, [fetchReports]);

  const filteredAlerts = useMemo(() => {
    if (!severity) return alertList;

    return alertList.filter(
      (alert) => normalizeSeverity(alert.severity) === normalizeSeverity(severity)
    );
  }, [alertList, severity]);

  const filteredLogs = useMemo(() => {
    if (!severity) return logList;

    if (severity === "Critical") {
      return logList.filter((log) => Number(log.metadata?.requestRate || 0) > 150);
    }

    if (severity === "High") {
      return logList.filter((log) => Number(log.metadata?.requestRate || 0) > 80);
    }

    return logList;
  }, [logList, severity]);

  const reportSummary = useMemo(() => {
    const critical = alertList.filter(
      (alert) => normalizeSeverity(alert.severity) === "critical"
    ).length;

    const high = alertList.filter(
      (alert) => normalizeSeverity(alert.severity) === "high"
    ).length;

    const resolved = alertList.filter(
      (alert) => String(alert.status).toLowerCase() === "resolved"
    ).length;

    const investigating = alertList.filter(
      (alert) => String(alert.status).toLowerCase() === "investigating"
    ).length;

    const avgRisk = alertList.length
      ? Math.round(
          alertList.reduce(
            (sum, alert) => sum + Number(alert.risk_score || alert.riskScore || 0),
            0
          ) / alertList.length
        )
      : 0;

    return {
      critical,
      high,
      resolved,
      investigating,
      avgRisk,
    };
  }, [alertList]);

  const handleExportAlerts = async () => {
    try {
      setExporting("alerts");
      setError("");

      const response = await reports.exportAlertsCsv(severity);
      downloadBlob(
        severity
          ? `threatlens-alerts-${severity.toLowerCase()}.csv`
          : "threatlens-alerts.csv",
        response.data
      );
    } catch (err) {
      console.error("Alerts export error:", err);
      setError(
        err?.response?.data?.message ||
          "Failed to export alerts. Only admin users can export reports."
      );
    } finally {
      setExporting("");
    }
  };

  const handleExportLogs = async () => {
    try {
      setExporting("logs");
      setError("");

      const response = await reports.exportLogsCsv();
      downloadBlob("threatlens-logs.csv", response.data);
    } catch (err) {
      console.error("Logs export error:", err);
      setError(
        err?.response?.data?.message ||
          "Failed to export logs. Only admin users can export reports."
      );
    } finally {
      setExporting("");
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Preparing real-time reports...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Reporting / Export Workspace</div>
          <h1>Reports</h1>
          <p>
            Generate real-time alert and telemetry reports for analysts, managers,
            audit reviews, and security investigation records.
          </p>
        </div>

        <div className="command-actions">
          <button
            type="button"
            className="secondary-btn"
            onClick={() => fetchReports(true)}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing..." : "Refresh Reports"}
          </button>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Socket</span>
          <strong>{socketState.connectionStatus}</strong>
          <small>{socketState.lastError || "Live report updates enabled"}</small>
        </div>

        <div className="metric-card">
          <span>Last Updated</span>
          <strong>{lastUpdated ? "Synced" : "Waiting"}</strong>
          <small>{formatDate(lastUpdated)}</small>
        </div>

        <div className="metric-card">
          <span>Alerts In Scope</span>
          <strong>{filteredAlerts.length}</strong>
          <small>Based on selected severity</small>
        </div>

        <div className="metric-card">
          <span>Logs In Scope</span>
          <strong>{filteredLogs.length}</strong>
          <small>Telemetry available for report</small>
        </div>
      </section>

      <section className="metrics-grid">
        <div className="metric-card danger">
          <span>Critical Alerts</span>
          <strong>{reportSummary.critical}</strong>
        </div>

        <div className="metric-card warning">
          <span>High Alerts</span>
          <strong>{reportSummary.high}</strong>
        </div>

        <div className="metric-card">
          <span>Investigating</span>
          <strong>{reportSummary.investigating}</strong>
        </div>

        <div className="metric-card">
          <span>Resolved</span>
          <strong>{reportSummary.resolved}</strong>
        </div>

        <div className="metric-card">
          <span>Average Risk</span>
          <strong>{reportSummary.avgRisk}</strong>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <div>
            <h2>Export Controls</h2>
            <p>
              Select a severity filter and export alert or log datasets from the
              current reporting workspace.
            </p>
          </div>

          <span className="live-badge">
            {socketState.connectionStatus === "connected"
              ? "Live reports active"
              : "Live channel inactive"}
          </span>
        </div>

        {!isAdmin && (
          <div className="error-message">
            Viewer access is read-only. CSV exports are restricted to the admin account.
          </div>
        )}

        <div className="action-row">
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <button
            type="button"
            className="scan-btn"
            disabled={!isAdmin || exporting === "alerts"}
            onClick={handleExportAlerts}
          >
            {exporting === "alerts" ? "Exporting..." : "Export Alerts CSV"}
          </button>

          <button
            type="button"
            className="scan-btn"
            disabled={!isAdmin || exporting === "logs"}
            onClick={handleExportLogs}
          >
            {exporting === "logs" ? "Exporting..." : "Export Logs CSV"}
          </button>
        </div>
      </section>

      <section className="card">
        <h3>Report Preview</h3>

        {filteredAlerts.length > 0 ? (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Alert</th>
                  <th>IP</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Timestamp</th>
                </tr>
              </thead>

              <tbody>
                {filteredAlerts.slice(0, 8).map((alert) => (
                  <tr key={alert._id}>
                    <td>{alert.type || alert.attackType || "Security Alert"}</td>
                    <td className="ip-cell">
                      {alert.ip || alert.src_ip || alert.source_ip || "-"}
                    </td>
                    <td>{alert.severity || "-"}</td>
                    <td>{alert.status || "New"}</td>
                    <td>{alert.risk_score ?? alert.riskScore ?? 50}</td>
                    <td>{formatDate(alert.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <h3>No report data available</h3>
            <p>Alerts matching the selected report filter will appear here.</p>
          </div>
        )}
      </section>
    </MainLayout>
  );
};

export default Reports;