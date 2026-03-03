import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";
import useSocket from "../hooks/useSocket";

const Alerts = () => {
  const [alertList, setAlertList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState({
    status: "",
    severity: "",
    search: "",
  });

  const limit = 20;

  const token = localStorage.getItem("accessToken");

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const res = await alerts.list(limit, page, filters);
      setAlertList(res.data.data);
      setTotal(res.data.pagination.total);
    } catch (err) {
      setError("Failed to fetch alerts");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": () => fetchAlerts(),
      "alerts:update": () => fetchAlerts(),
    }),
    [fetchAlerts]
  );

  useSocket(token, socketHandlers);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleScan = async () => {
    try {
      setScanning(true);
      await alerts.scan();
      fetchAlerts();
    } catch (err) {
      setError("Scan failed");
      console.error(err);
    } finally {
      setScanning(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "severity-critical";
      case "HIGH":
        return "severity-high";
      case "MEDIUM":
        return "severity-medium";
      case "LOW":
        return "severity-low";
      default:
        return "";
    }
  };

  if (loading) return <MainLayout><div className="loading">Loading...</div></MainLayout>;

  const totalPages = Math.ceil(total / limit);

  return (
    <MainLayout>
      <h1>Security Alerts</h1>
      <p>All detected intrusions and suspicious activities are listed here.</p>

      {error && <div className="error-message">{error}</div>}

      <div className="controls">
        <button
          onClick={handleScan}
          disabled={scanning}
          className="scan-btn"
        >
          {scanning ? "🔄 Scanning..." : "🚀 Run Scan"}
        </button>
        <input
          className="search-input"
          placeholder="Search attack type or keyword"
          value={filters.search}
          onChange={(e) => {
            setPage(1);
            setFilters({ ...filters, search: e.target.value });
          }}
        />
        <select
          value={filters.severity}
          onChange={(e) => {
            setPage(1);
            setFilters({ ...filters, severity: e.target.value });
          }}
        >
          <option value="">All severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select
          value={filters.status}
          onChange={(e) => {
            setPage(1);
            setFilters({ ...filters, status: e.target.value });
          }}
        >
          <option value="">All statuses</option>
          <option value="New">New</option>
          <option value="Acknowledged">Acknowledged</option>
          <option value="Investigating">Investigating</option>
          <option value="Resolved">Resolved</option>
          <option value="False Positive">False Positive</option>
        </select>
      </div>

      <div className="card alert-card">
        {alertList.length > 0 ? (
          <>
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>IP Address</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {alertList.map((alert, idx) => (
                  <tr key={idx}>
                    <td>
                      <Link to={`/alerts/${alert._id}`} className="alert-link">
                        {alert.type}
                      </Link>
                    </td>
                    <td className="ip-cell">{alert.ip}</td>
                    <td>
                      <span className={`severity ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>{alert.status}</td>
                    <td>{new Date(alert.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <button
                onClick={() => setPage(Math.max(page - 1, 1))}
                disabled={page === 1}
              >
                ← Previous
              </button>
              <span>
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage(Math.min(page + 1, totalPages))}
                disabled={page === totalPages}
              >
                Next →
              </button>
            </div>
          </>
        ) : (
          <p>No alerts detected yet. Run a scan to check for threats.</p>
        )}
      </div>
    </MainLayout>
  );
};

export default Alerts;
