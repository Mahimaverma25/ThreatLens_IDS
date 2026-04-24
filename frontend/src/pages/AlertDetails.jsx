import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";
import useSocket from "../hooks/useSocket";
import { useAuth } from "../context/AuthContext";

const resolveSocketPayload = (payload) => payload?.data || payload;

const formatDate = (value) => {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
};

const formatBytes = (value) => {
  const bytes = Number(value || 0);
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
};

const getSeverityClass = (severity = "") => {
  switch (String(severity).toLowerCase()) {
    case "critical":
      return "severity-critical";
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    default:
      return "severity-unknown";
  }
};

const AlertDetails = () => {
  const { id } = useParams();
  const { user } = useAuth();

  const [alert, setAlert] = useState(null);
  const [status, setStatus] = useState("New");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [lastLiveUpdate, setLastLiveUpdate] = useState(null);

  const token = localStorage.getItem("accessToken");
  const isAdmin = user?.role === "admin";
  const mountedRef = useRef(true);
  const refreshTimerRef = useRef(null);

  const fetchAlert = useCallback(
    async (silent = false) => {
      try {
        if (silent) setRefreshing(true);
        else setLoading(true);

        setError("");

        const response = await alerts.get(id);
        const data = response?.data?.data;

        if (!data) throw new Error("Alert not found");

        if (!mountedRef.current) return;

        setAlert(data);
        setStatus(data.status || "New");
      } catch (err) {
        console.error("Alert details fetch error:", err);

        if (mountedRef.current) {
          setError(
            err?.response?.data?.message ||
              "Failed to load alert details. Please check backend connection."
          );
        }
      } finally {
        if (mountedRef.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [id]
  );

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => fetchAlert(true), 350);
  }, [fetchAlert]);

  const socketHandlers = useMemo(
    () => ({
      "alerts:update": (payload) => {
        const updated = resolveSocketPayload(payload);

        if (updated?._id === id || updated?.id === id) {
          setLastLiveUpdate(new Date());
          setAlert((current) => (current ? { ...current, ...updated } : current));
          scheduleRefresh();
        }
      },

      "alerts:new": (payload) => {
        const incoming = resolveSocketPayload(payload);

        if (incoming?._id === id || incoming?.id === id) {
          setLastLiveUpdate(new Date());
          scheduleRefresh();
        }
      },

      "logs:new": (payload) => {
        const log = resolveSocketPayload(payload);
        const relatedIds = alert?.relatedLogs?.map((item) => item?._id) || [];

        if (relatedIds.includes(log?._id)) {
          setLastLiveUpdate(new Date());
          scheduleRefresh();
        }
      },

      "collector:heartbeat": () => {
        setLastLiveUpdate(new Date());
      },
    }),
    [id, alert?.relatedLogs, scheduleRefresh]
  );

  const socketState = useSocket(token, socketHandlers);

  useEffect(() => {
    mountedRef.current = true;
    fetchAlert();

    return () => {
      mountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
    };
  }, [fetchAlert]);

  const evidenceSummary = useMemo(() => {
    const relatedLogs = alert?.relatedLogs || [];

    return relatedLogs.reduce(
      (acc, log) => {
        acc.totalBytes += Number(log.metadata?.bytes || 0);
        acc.failedAttempts += Number(log.metadata?.failedAttempts || 0);
        acc.highestRate = Math.max(acc.highestRate, Number(log.metadata?.requestRate || 0));
        acc.flowCount += Number(log.metadata?.flowCount || 0);
        return acc;
      },
      {
        totalBytes: 0,
        failedAttempts: 0,
        highestRate: 0,
        flowCount: 0,
      }
    );
  }, [alert]);

  const handleUpdate = async () => {
    try {
      setSaving(true);
      setError("");

      await alerts.update(id, {
        status,
        note: note.trim() || undefined,
      });

      setNote("");
      await fetchAlert(true);
    } catch (err) {
      console.error("Alert update error:", err);
      setError(
        err?.response?.data?.message ||
          "Failed to update alert. Only admin users can update alert status."
      );
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading alert investigation...</div>
      </MainLayout>
    );
  }

  if (!alert) {
    return (
      <MainLayout>
        <div className="error-message">{error || "Alert not found"}</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Alerts / Investigation</div>
          <h1>Alert Details</h1>
          <p>
            Review live evidence, related logs, severity, confidence, analyst notes,
            and investigation status for this security alert.
          </p>
        </div>

        <div className="command-actions">
          <Link to="/alerts" className="secondary-btn">
            Back to Alerts
          </Link>

          <button
            type="button"
            className="primary-btn"
            onClick={() => fetchAlert(true)}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Socket</span>
          <strong>{socketState.connectionStatus}</strong>
          <small>{socketState.lastError || "Live investigation channel"}</small>
        </div>

        <div className="metric-card">
          <span>Live Update</span>
          <strong>{lastLiveUpdate ? "Received" : "Waiting"}</strong>
          <small>{lastLiveUpdate ? formatDate(lastLiveUpdate) : "No live update yet"}</small>
        </div>

        <div className="metric-card">
          <span>Severity</span>
          <strong>{alert.severity || "Unknown"}</strong>
          <small>Current alert priority</small>
        </div>

        <div className="metric-card">
          <span>Status</span>
          <strong>{alert.status || "New"}</strong>
          <small>Investigation state</small>
        </div>
      </section>

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Evidence Logs</span>
          <strong>{alert.relatedLogs?.length || 0}</strong>
        </div>

        <div className="metric-card">
          <span>Evidence Bytes</span>
          <strong>{formatBytes(evidenceSummary.totalBytes)}</strong>
        </div>

        <div className="metric-card">
          <span>Failed Attempts</span>
          <strong>{evidenceSummary.failedAttempts}</strong>
        </div>

        <div className="metric-card">
          <span>Highest Request Rate</span>
          <strong>{evidenceSummary.highestRate}/min</strong>
        </div>

        <div className="metric-card">
          <span>Total Flow Count</span>
          <strong>{evidenceSummary.flowCount}</strong>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <div>
            <h2>{alert.type || alert.attackType || "Security Alert"}</h2>
            <p>{alert.description || alert.message || "No alert description available."}</p>
          </div>

          <span className={`severity ${getSeverityClass(alert.severity)}`}>
            {alert.severity || "Unknown"}
          </span>
        </div>

        <div className="details-grid">
          <div>
            <strong>Alert ID:</strong> {alert.alertId || alert._id}
          </div>
          <div>
            <strong>Attack Type:</strong> {alert.attackType || alert.type || "-"}
          </div>
          <div>
            <strong>Source IP:</strong>{" "}
            <span className="mono-text">
              {alert.ip || alert.src_ip || alert.source_ip || "-"}
            </span>
          </div>
          <div>
            <strong>Source:</strong> {alert.source || "ThreatLens"}
          </div>
          <div>
            <strong>Status:</strong> {alert.status || "New"}
          </div>
          <div>
            <strong>Confidence:</strong>{" "}
            {Math.round(Number(alert.confidence || 0) * 100)}%
          </div>
          <div>
            <strong>Risk Score:</strong> {alert.risk_score ?? alert.riskScore ?? 50}
          </div>
          <div>
            <strong>Detected:</strong> {formatDate(alert.timestamp)}
          </div>
          <div>
            <strong>Resolved:</strong> {formatDate(alert.resolvedAt)}
          </div>
        </div>
      </section>

      <section className="card">
        <h3>Analyst Actions</h3>

        {isAdmin ? (
          <div className="action-row">
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="New">New</option>
              <option value="Acknowledged">Acknowledged</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="False Positive">False Positive</option>
            </select>

            <input
              className="note-input"
              placeholder="Add analyst note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />

            <button
              type="button"
              className="scan-btn"
              onClick={handleUpdate}
              disabled={saving}
            >
              {saving ? "Saving..." : "Save Update"}
            </button>
          </div>
        ) : (
          <p>Viewer access is read-only. Only admin can update alert status and notes.</p>
        )}
      </section>

      <section className="card">
        <h3>Evidence Logs</h3>

        {alert.relatedLogs?.length > 0 ? (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Message</th>
                  <th>Protocol</th>
                  <th>Bytes</th>
                  <th>Flags</th>
                  <th>Dest Port</th>
                  <th>Req Rate</th>
                  <th>Flow Count</th>
                  <th>IP</th>
                  <th>Timestamp</th>
                </tr>
              </thead>

              <tbody>
                {alert.relatedLogs.map((log) => (
                  <tr key={log._id}>
                    <td>{log.message || log.event_type || "-"}</td>
                    <td>{log.metadata?.protocol || log.protocol || "-"}</td>
                    <td>{formatBytes(log.metadata?.bytes)}</td>
                    <td>
                      {Array.isArray(log.metadata?.flags)
                        ? log.metadata.flags.join(", ")
                        : "-"}
                    </td>
                    <td className="mono-text">
                      {log.metadata?.destinationPort || log.metadata?.port || "-"}
                    </td>
                    <td>{log.metadata?.requestRate || "-"}</td>
                    <td>{log.metadata?.flowCount || "-"}</td>
                    <td className="ip-cell">{log.ip || log.src_ip || "-"}</td>
                    <td>{formatDate(log.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <h3>No related logs available</h3>
            <p>Evidence logs will appear here when linked telemetry is available.</p>
          </div>
        )}
      </section>

      <section className="card">
        <h3>Analyst Notes</h3>

        {alert.analystNotes?.length > 0 ? (
          <ul className="notes-list">
            {alert.analystNotes.map((item, index) => (
              <li key={`${item.timestamp || index}-${index}`}>
                <div>{item.note}</div>
                <small>{formatDate(item.timestamp)}</small>
              </li>
            ))}
          </ul>
        ) : (
          <p>No analyst notes yet.</p>
        )}
      </section>
    </MainLayout>
  );
};

export default AlertDetails;