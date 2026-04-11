import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, logs } from "../services/api";

const downloadCsv = (filename, rows) => {
  const blob = new Blob([rows.join("\n")], { type: "text/csv;charset=utf-8;" });
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
  const [alertList, setAlertList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        setError("");
        const [alertResponse, logResponse] = await Promise.all([alerts.list(200, 1), logs.list(200, 1)]);
        setAlertList(alertResponse?.data?.data ?? []);
        setLogList(logResponse?.data?.data ?? []);
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
            onClick={() =>
              downloadCsv(
                "threatlens-alerts.csv",
                [
                  "type,ip,severity,status,confidence,risk_score,timestamp",
                  ...filteredAlerts.map((alert) =>
                    [
                      alert.type,
                      alert.ip,
                      alert.severity,
                      alert.status,
                      alert.confidence,
                      alert.risk_score,
                      alert.timestamp
                    ].join(",")
                  )
                ]
              )
            }
          >
            Export Alerts CSV
          </button>

          <button
            className="scan-btn"
            onClick={() =>
              downloadCsv(
                "threatlens-logs.csv",
                [
                  "message,ip,protocol,bytes,destination_port,request_rate,timestamp",
                  ...filteredLogs.map((log) =>
                    [
                      `"${String(log.message || "").replace(/"/g, '""')}"`,
                      log.ip,
                      log.metadata?.protocol || "",
                      log.metadata?.bytes || 0,
                      log.metadata?.destinationPort || log.metadata?.port || "",
                      log.metadata?.requestRate || 0,
                      log.timestamp || ""
                    ].join(",")
                  )
                ]
              )
            }
          >
            Export Logs CSV
          </button>
        </div>
      </div>
    </MainLayout>
  );
};

export default Reports;
