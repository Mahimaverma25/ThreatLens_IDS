import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

  const abortRef = useRef(null);
  const isMountedRef = useRef(true);

  /* ================= FETCH ALERTS ================= */

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      if (abortRef.current) {
        abortRef.current.abort();
      }

      abortRef.current = new AbortController();

      const res = await alerts.list(limit, page, filters);

      const data = res?.data?.data ?? [];
      const pagination = res?.data?.pagination ?? {};

      if (!isMountedRef.current) return;

      setAlertList(data);
      setTotal(pagination.total ?? data.length);
    } catch (err) {
      console.error("Alerts fetch error:", err);

      if (isMountedRef.current) {
        setError("Failed to fetch alerts");
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [page, filters]);

  /* ================= SOCKET ================= */

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": () => fetchAlerts(),
      "alerts:update": () => fetchAlerts(),
    }),
    [fetchAlerts]
  );

  useSocket(token, socketHandlers);

  /* ================= INIT LOAD ================= */

  useEffect(() => {
    isMountedRef.current = true;
    fetchAlerts();

    return () => {
      isMountedRef.current = false;

      if (abortRef.current) {
        abortRef.current.abort();
      }
    };
  }, [fetchAlerts]);

  /* ================= SCAN ================= */

  const handleScan = async () => {
    try {
      setScanning(true);
      setError("");

      await alerts.scan();

      // refresh after scan
      fetchAlerts();
    } catch (err) {
      console.error("Scan error:", err);
      setError("Scan failed");
    } finally {
      setScanning(false);
    }
  };

  /* ================= SEVERITY COLOR ================= */

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

  /* ================= LOADING ================= */

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading alerts...</div>
      </MainLayout>
    );
  }

  const totalPages = Math.max(1, Math.ceil(total / limit));

  /* ================= UI ================= */

  return (
    <MainLayout>
      <h1>Security Alerts</h1>
      <p>All detected intrusions and suspicious activities are listed here.</p>

      {error && <div className="error-message">{error}</div>}

      {/* ================= CONTROLS ================= */}

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
            setFilters((prev) => ({
              ...prev,
              search: e.target.value,
            }));
          }}
        />

        <select
          value={filters.severity}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({
              ...prev,
              severity: e.target.value,
            }));
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
            setFilters((prev) => ({
              ...prev,
              status: e.target.value,
            }));
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

      {/* ================= ALERT TABLE ================= */}

      <div className="card alert-card">
        {alertList?.length > 0 ? (
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
                {alertList.map((alert) => (
                  <tr key={alert._id}>
                    <td>
                      <Link
                        to={`/alerts/${alert._id}`}
                        className="alert-link"
                      >
                        {alert.type}
                      </Link>
                    </td>

                    <td className="ip-cell">{alert.ip}</td>

                    <td>
                      <span
                        className={`severity ${getSeverityColor(
                          alert.severity
                        )}`}
                      >
                        {alert.severity}
                      </span>
                    </td>

                    <td>{alert.status}</td>

                    <td>
                      {alert.timestamp
                        ? new Date(alert.timestamp).toLocaleString()
                        : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* ================= PAGINATION ================= */}

            <div className="pagination">
              <button
                onClick={() => setPage((p) => Math.max(p - 1, 1))}
                disabled={page === 1}
              >
                ← Previous
              </button>

              <span>
                Page {page} of {totalPages}
              </span>

              <button
                onClick={() =>
                  setPage((p) => Math.min(p + 1, totalPages))
                }
                disabled={page >= totalPages}
              >
                Next →
              </button>
            </div>
          </>
        ) : (
          <p>
            No alerts detected yet. Run a scan to check for threats.
          </p>
        )}
      </div>
    </MainLayout>
  );
};

export default Alerts;