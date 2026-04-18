import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";
import useSocket from "../hooks/useSocket";
import { useAuth } from "../context/AuthContext";

const Alerts = () => {
  const { user } = useAuth();
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
    source: ""
  });

  const limit = 20;
  const isAdmin = user?.role === "admin";
  const token = localStorage.getItem("accessToken");
  const abortRef = useRef(null);
  const isMountedRef = useRef(true);
  const refreshTimerRef = useRef(null);

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

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchAlerts, 300);
      },
      "alerts:update": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchAlerts, 300);
      }
    }),
    [fetchAlerts]
  );

  useSocket(token, socketHandlers);

  useEffect(() => {
    isMountedRef.current = true;
    fetchAlerts();

    return () => {
      isMountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
      if (abortRef.current) {
        abortRef.current.abort();
      }
    };
  }, [fetchAlerts]);

  const handleScan = async () => {
    try {
      setScanning(true);
      setError("");
      await alerts.scan();
      fetchAlerts();
    } catch (err) {
      console.error("Scan error:", err);
      setError("Scan failed");
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

  const alertSummary = useMemo(() => {
    const totals = alertList.reduce(
      (accumulator, alert) => {
        accumulator.confidence += Number(alert.confidence || 0);
        accumulator.risk += Number(alert.risk_score || 0);

        if (alert.severity === "Critical") accumulator.critical += 1;
        if (alert.severity === "High") accumulator.high += 1;
        if (alert.status === "Investigating") accumulator.investigating += 1;
        return accumulator;
      },
      { confidence: 0, risk: 0, critical: 0, high: 0, investigating: 0 }
    );

    return {
      avgConfidence: alertList.length ? Math.round((totals.confidence / alertList.length) * 100) : 0,
      avgRisk: alertList.length ? Math.round(totals.risk / alertList.length) : 0,
      critical: totals.critical,
      high: totals.high,
      investigating: totals.investigating
    };
  }, [alertList]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading alerts...</div>
      </MainLayout>
    );
  }

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Detection / Incidents</div>
          <h1>Security Alerts</h1>
          <p>
            Ranked intrusion alerts with severity, confidence, risk score, and analyst status.
          </p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Visible Alerts</span>
          <strong>{alertList.length}</strong>
        </div>
        <div className="metric-card">
          <span>Critical</span>
          <strong>{alertSummary.critical}</strong>
        </div>
        <div className="metric-card">
          <span>High Severity</span>
          <strong>{alertSummary.high}</strong>
        </div>
        <div className="metric-card">
          <span>Investigating</span>
          <strong>{alertSummary.investigating}</strong>
        </div>
        <div className="metric-card">
          <span>Avg Confidence</span>
          <strong>{alertSummary.avgConfidence}%</strong>
        </div>
        <div className="metric-card">
          <span>Avg Risk Score</span>
          <strong>{alertSummary.avgRisk}</strong>
        </div>
      </section>

      <div className="controls">
        {isAdmin ? (
          <button onClick={handleScan} disabled={scanning} className="scan-btn">
            {scanning ? "Scanning..." : "Run Scan"}
          </button>
        ) : (
          <button disabled className="scan-btn">
            Read-only access
          </button>
        )}

        <input
          className="search-input"
          placeholder="Search attack type or keyword"
          value={filters.search}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({ ...prev, search: e.target.value }));
          }}
        />

        <select
          value={filters.source}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({ ...prev, source: e.target.value }));
          }}
        >
          <option value="">All sources</option>
          <option value="snort">Live Snort</option>
          <option value="ids-engine">IDS Scan</option>
        </select>

        <select
          value={filters.severity}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({ ...prev, severity: e.target.value }));
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
            setFilters((prev) => ({ ...prev, status: e.target.value }));
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
        {alertList?.length > 0 ? (
          <>
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>IP Address</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Timestamp</th>
                </tr>
              </thead>

              <tbody>
                {alertList.map((alert) => (
                  <tr key={alert._id}>
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
                    <td>{Math.round((alert.confidence || 0) * 100)}%</td>
                    <td>{alert.risk_score ?? 50}</td>
                    <td>{alert.status}</td>
                    <td>
                      {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <button
                onClick={() => setPage((p) => Math.max(p - 1, 1))}
                disabled={page === 1}
              >
                Previous
              </button>

              <span>
                Page {page} of {totalPages}
              </span>

              <button
                onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
                disabled={page >= totalPages}
              >
                Next
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
