import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";
import useSocket from "../hooks/useSocket";

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

  /* ================= FETCH ALERT ================= */

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

  /* ================= SOCKET ================= */

  const socketHandlers = useMemo(
    () => ({
      "alerts:update": (updated) => {
        if (updated?._id === id) {
          fetchAlert();
        }
      },
    }),
    [fetchAlert, id]
  );

  useSocket(token, socketHandlers);

  /* ================= INIT LOAD ================= */

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

  /* ================= UPDATE ALERT ================= */

  const handleUpdate = async () => {
    try {
      setSaving(true);
      setError("");

      await alerts.update(id, {
        status,
        note: note?.trim() || undefined,
      });

      setNote("");

      // refresh after update
      fetchAlert();
    } catch (err) {
      console.error("Update error:", err);
      setError("Failed to update alert");
    } finally {
      setSaving(false);
    }
  };

  /* ================= LOADING ================= */

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading alert...</div>
      </MainLayout>
    );
  }

  /* ================= NOT FOUND ================= */

  if (!alert) {
    return (
      <MainLayout>
        <div className="error-message">
          {error || "Alert not found"}
        </div>
      </MainLayout>
    );
  }

  /* ================= UI ================= */

  return (
    <MainLayout>
      <h1>Alert Details</h1>
      <p>Review the full evidence and manage the alert lifecycle.</p>

      {error && <div className="error-message">{error}</div>}

      {/* ================= OVERVIEW ================= */}

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
            <strong>Source IP:</strong> {alert.ip}
          </div>

          <div>
            <strong>Severity:</strong> {alert.severity}
          </div>

          <div>
            <strong>Status:</strong> {alert.status}
          </div>

          <div>
            <strong>Detected:</strong>{" "}
            {alert.timestamp
              ? new Date(alert.timestamp).toLocaleString()
              : "-"}
          </div>

          <div>
            <strong>Resolved:</strong>{" "}
            {alert.resolvedAt
              ? new Date(alert.resolvedAt).toLocaleString()
              : "-"}
          </div>
        </div>
      </div>

      {/* ================= ACTIONS ================= */}

      <div className="card">
        <h3>Analyst Actions</h3>

        <div className="action-row">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
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

          <button
            className="scan-btn"
            onClick={handleUpdate}
            disabled={saving}
          >
            {saving ? "Saving..." : "Save"}
          </button>
        </div>
      </div>

      {/* ================= EVIDENCE LOGS ================= */}

      <div className="card">
        <h3>Evidence Logs</h3>

        {alert.relatedLogs?.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Message</th>
                <th>Level</th>
                <th>Source</th>
                <th>IP</th>
                <th>Timestamp</th>
              </tr>
            </thead>

            <tbody>
              {alert.relatedLogs.map((log) => (
                <tr key={log._id}>
                  <td>{log.message}</td>
                  <td>{log.level}</td>
                  <td>{log.source}</td>
                  <td>{log.ip}</td>
                  <td>
                    {log.timestamp
                      ? new Date(log.timestamp).toLocaleString()
                      : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No related logs available.</p>
        )}
      </div>

      {/* ================= NOTES ================= */}

      <div className="card">
        <h3>Analyst Notes</h3>

        {alert.analystNotes?.length > 0 ? (
          <ul className="notes-list">
            {alert.analystNotes.map((item, idx) => (
              <li key={`${item.timestamp || idx}-${idx}`}>
                <div>{item.note}</div>
                <small>
                  {item.timestamp
                    ? new Date(item.timestamp).toLocaleString()
                    : "-"}
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