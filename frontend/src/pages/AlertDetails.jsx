import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";
import useSocket from "../hooks/useSocket";

const formatBytes = (value) => {
  const bytes = Number(value || 0);

  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
};

const AlertDetails = () => {
  const { id } = useParams();

  const [alert, setAlert] = useState(null);
  const [status, setStatus] = useState("");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const token = localStorage.getItem("accessToken");
  const abortRef = useRef(null);
  const isMountedRef = useRef(true);

  const fetchAlert = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      if (abortRef.current) {
        abortRef.current.abort();
      }

      abortRef.current = new AbortController();

      const res = await alerts.get(id);
      const data = res?.data?.data;

      if (!data) throw new Error("No alert found");

      if (isMountedRef.current) {
        setAlert(data);
        setStatus(data.status || "");
      }
    } catch (err) {
      console.error("Alert fetch error:", err);
      if (isMountedRef.current) {
        setError("Failed to load alert");
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [id]);

  const socketHandlers = useMemo(
    () => ({
      "alerts:update": (updated) => {
        if (updated?._id === id) {
          fetchAlert();
        }
      }
    }),
    [fetchAlert, id]
  );

  useSocket(token, socketHandlers);

  useEffect(() => {
    isMountedRef.current = true;
    fetchAlert();

    return () => {
      isMountedRef.current = false;
      if (abortRef.current) {
        abortRef.current.abort();
      }
    };
  }, [fetchAlert]);

  const handleUpdate = async () => {
    try {
      setSaving(true);
      setError("");

      await alerts.update(id, {
        status,
        note: note?.trim() || undefined
      });

      setNote("");
      fetchAlert();
    } catch (err) {
      console.error("Update error:", err);
      setError("Failed to update alert");
    } finally {
      setSaving(false);
    }
  };

  const evidenceSummary = useMemo(() => {
    const relatedLogs = alert?.relatedLogs || [];

    return relatedLogs.reduce(
      (accumulator, log) => {
        accumulator.totalBytes += Number(log.metadata?.bytes || 0);
        accumulator.failedAttempts += Number(log.metadata?.failedAttempts || 0);
        accumulator.highestRate = Math.max(
          accumulator.highestRate,
          Number(log.metadata?.requestRate || 0)
        );
        return accumulator;
      },
      { totalBytes: 0, failedAttempts: 0, highestRate: 0 }
    );
  }, [alert]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading alert...</div>
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
          <div className="command-eyebrow">ThreatLens / Alert / Investigation</div>
          <h1>Alert Details</h1>
          <p>Review evidence, telemetry, and analyst actions for this security event.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Severity</span>
          <strong>{alert.severity}</strong>
        </div>
        <div className="metric-card">
          <span>Status</span>
          <strong>{alert.status}</strong>
        </div>
        <div className="metric-card">
          <span>Evidence Bytes</span>
          <strong>{formatBytes(evidenceSummary.totalBytes)}</strong>
        </div>
        <div className="metric-card">
          <span>Highest Request Rate</span>
          <strong>{evidenceSummary.highestRate}/min</strong>
        </div>
      </section>

      <div className="card">
        <h3>Overview</h3>

        <div className="details-grid">
          <div>
            <strong>Alert ID:</strong> {alert.alertId}
          </div>
          <div>
            <strong>Attack Type:</strong> {alert.attackType}
          </div>
          <div>
            <strong>Source IP:</strong> <span className="mono-text">{alert.ip}</span>
          </div>
          <div>
            <strong>Severity:</strong> {alert.severity}
          </div>
          <div>
            <strong>Status:</strong> {alert.status}
          </div>
          <div>
            <strong>Confidence:</strong> {Math.round((alert.confidence || 0) * 100)}%
          </div>
          <div>
            <strong>Risk Score:</strong> {alert.risk_score}
          </div>
          <div>
            <strong>Detected:</strong> {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "-"}
          </div>
          <div>
            <strong>Resolved:</strong> {alert.resolvedAt ? new Date(alert.resolvedAt).toLocaleString() : "-"}
          </div>
          <div>
            <strong>Related Logs:</strong> {alert.relatedLogs?.length || 0}
          </div>
          <div>
            <strong>Failed Attempts:</strong> {evidenceSummary.failedAttempts}
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Analyst Actions</h3>

        <div className="action-row">
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
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
            onChange={(e) => setNote(e.target.value)}
          />

          <button className="scan-btn" onClick={handleUpdate} disabled={saving}>
            {saving ? "Saving..." : "Save"}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Evidence Logs</h3>

        {alert.relatedLogs?.length > 0 ? (
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
                  <td>{log.message}</td>
                  <td>{log.metadata?.protocol || "-"}</td>
                  <td>{formatBytes(log.metadata?.bytes)}</td>
                  <td>{Array.isArray(log.metadata?.flags) ? log.metadata.flags.join(", ") : "-"}</td>
                  <td className="mono-text">{log.metadata?.destinationPort || log.metadata?.port || "-"}</td>
                  <td>{log.metadata?.requestRate || "-"}</td>
                  <td>{log.metadata?.flowCount || "-"}</td>
                  <td className="ip-cell">{log.ip}</td>
                  <td>{log.timestamp ? new Date(log.timestamp).toLocaleString() : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No related logs available.</p>
        )}
      </div>

      <div className="card">
        <h3>Analyst Notes</h3>

        {alert.analystNotes?.length > 0 ? (
          <ul className="notes-list">
            {alert.analystNotes.map((item, idx) => (
              <li key={`${item.timestamp || idx}-${idx}`}>
                <div>{item.note}</div>
                <small>
                  {item.timestamp ? new Date(item.timestamp).toLocaleString() : "-"}
                </small>
              </li>
            ))}
          </ul>
        ) : (
          <p>No notes yet.</p>
        )}
      </div>
    </MainLayout>
  );
};

export default AlertDetails;
