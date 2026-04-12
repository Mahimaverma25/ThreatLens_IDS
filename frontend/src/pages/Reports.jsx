import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { reports } from "../services/api";
import { useAuth } from "../context/AuthContext";

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

const Reports = () => {
  const { user } = useAuth();
  const [alertList, setAlertList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const isAdmin = user?.role === "admin";

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        setError("");
        const response = await reports.summary();
        setAlertList(response?.data?.data?.alerts ?? []);
        setLogList(response?.data?.data?.logs ?? []);
      } catch (fetchError) {
        console.error("Reports fetch error:", fetchError);
        setError("Failed to load reporting data");
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

  const filteredAlerts = useMemo(() => {
    return severity ? alertList.filter((alert) => alert.severity === severity) : alertList;
  }, [alertList, severity]);

  const filteredLogs = useMemo(() => {
    if (!severity) return logList;
    return logList.filter((log) => (severity === "Critical" ? Number(log.metadata?.requestRate || 0) > 150 : true));
  }, [logList, severity]);

  const handleExportAlerts = async () => {
    try {
      const response = await reports.exportAlertsCsv(severity);
      downloadBlob("threatlens-alerts.csv", response.data);
    } catch (exportError) {
      console.error("Alerts export error:", exportError);
      setError("Failed to export alerts");
    }
  };

  const handleExportLogs = async () => {
    try {
      const response = await reports.exportLogsCsv();
      downloadBlob("threatlens-logs.csv", response.data);
    } catch (exportError) {
      console.error("Logs export error:", exportError);
      setError("Failed to export logs");
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Preparing reports...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Reporting / export workspace</div>
          <h1>Reports</h1>
          <p>Generate filtered exports from your current alerts and telemetry for analysts, managers, and audit reviews.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Alerts In Scope</span>
          <strong>{filteredAlerts.length}</strong>
        </div>
        <div className="metric-card">
          <span>Logs In Scope</span>
          <strong>{filteredLogs.length}</strong>
        </div>
        <div className="metric-card">
          <span>Critical Alerts</span>
          <strong>{alertList.filter((alert) => alert.severity === "Critical").length}</strong>
        </div>
        <div className="metric-card">
          <span>Resolved Alerts</span>
          <strong>{alertList.filter((alert) => alert.status === "Resolved").length}</strong>
        </div>
      </section>

      <div className="card">
        <h3>Export Controls</h3>
        {!isAdmin && <p>Viewer access is read-only. Report exports are restricted to the admin account.</p>}
        <div className="action-row">
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <button
            className="scan-btn"
            disabled={!isAdmin}
            onClick={handleExportAlerts}
          >
            Export Alerts CSV
          </button>

          <button
            className="scan-btn"
            disabled={!isAdmin}
            onClick={handleExportLogs}
          >
            Export Logs CSV
          </button>
        </div>
      </div>
    </MainLayout>
  );
};

export default Reports;
