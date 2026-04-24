import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";
import useSocket from "../hooks/useSocket";

const LIMIT = 20;

const resolveSocketAlert = (payload) => payload?.data || payload;

const formatTimestamp = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const normalizeSeverity = (severity = "") => String(severity).toLowerCase();

const getSeverityClass = (severity) => {
  switch (normalizeSeverity(severity)) {
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

const Alerts = () => {
  const [alertList, setAlertList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [collectorHeartbeat, setCollectorHeartbeat] = useState(null);

  const [filters, setFilters] = useState({
    status: "",
    severity: "",
    source: "",
    search: "",
  });

  const token = localStorage.getItem("accessToken");
  const alertListRef = useRef([]);
  const refreshTimerRef = useRef(null);
  const isMountedRef = useRef(true);

  useEffect(() => {
    alertListRef.current = alertList;
  }, [alertList]);

  const hasActiveFilters = useMemo(() => {
    return Object.values(filters).some((value) => String(value || "").trim() !== "");
  }, [filters]);

  const fetchAlerts = useCallback(
    async (silent = false) => {
      try {
        if (silent) setRefreshing(true);
        else setLoading(true);

        setError("");

        const response = await alerts.list(LIMIT, page, filters);

        const data = response?.data?.data || [];
        const pagination = response?.data?.pagination || {};

        if (!isMountedRef.current) return;

        setAlertList(Array.isArray(data) ? data : []);
        setTotal(pagination.total ?? data.length ?? 0);
      } catch (err) {
        console.error("Alerts fetch error:", err);

        if (isMountedRef.current) {
          setError(
            err?.response?.data?.message ||
              "Failed to fetch alerts. Please check backend connection."
          );
        }
      } finally {
        if (isMountedRef.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [page, filters]
  );

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => fetchAlerts(true), 350);
  }, [fetchAlerts]);

  const mergeIncomingAlert = useCallback(
    (incoming, prepend = false) => {
      if (!incoming?._id) {
        scheduleRefresh();
        return;
      }

      const exists = alertListRef.current.some((item) => item._id === incoming._id);

      setAlertList((current) => {
        const updated = current.map((item) =>
          item._id === incoming._id ? { ...item, ...incoming } : item
        );

        if (exists) {
          return updated.sort(
            (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
          );
        }

        const merged = prepend ? [incoming, ...updated] : [...updated, incoming];

        return merged
          .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0))
          .slice(0, LIMIT);
      });

      if (!exists) {
        setTotal((current) => current + 1);
      }
    },
    [scheduleRefresh]
  );

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": (payload) => {
        const incoming = resolveSocketAlert(payload);

        if (page !== 1 || hasActiveFilters) {
          scheduleRefresh();
          return;
        }

        mergeIncomingAlert(incoming, true);
      },

      "alerts:update": (payload) => {
        const incoming = resolveSocketAlert(payload);

        if (page !== 1 || hasActiveFilters) {
          scheduleRefresh();
          return;
        }

        mergeIncomingAlert(incoming, false);
      },

      "collector:heartbeat": (payload) => {
        setCollectorHeartbeat(payload?.data || payload || null);
      },
    }),
    [page, hasActiveFilters, scheduleRefresh, mergeIncomingAlert]
  );

  const socketState = useSocket(token, socketHandlers);

  useEffect(() => {
    isMountedRef.current = true;
    fetchAlerts();

    return () => {
      isMountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
    };
  }, [fetchAlerts]);

  const alertSummary = useMemo(() => {
    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      investigating: 0,
      avgConfidence: 0,
      avgRisk: 0,
    };

    if (!alertList.length) return summary;

    let confidenceTotal = 0;
    let riskTotal = 0;

    alertList.forEach((alert) => {
      const severity = normalizeSeverity(alert.severity);

      if (severity === "critical") summary.critical += 1;
      if (severity === "high") summary.high += 1;
      if (severity === "medium") summary.medium += 1;
      if (severity === "low") summary.low += 1;

      if (String(alert.status).toLowerCase() === "investigating") {
        summary.investigating += 1;
      }

      confidenceTotal += Number(alert.confidence || 0);
      riskTotal += Number(alert.risk_score || alert.riskScore || 0);
    });

    summary.avgConfidence = Math.round((confidenceTotal / alertList.length) * 100);
    summary.avgRisk = Math.round(riskTotal / alertList.length);

    return summary;
  }, [alertList]);

  const totalPages = Math.max(1, Math.ceil(total / LIMIT));

  const updateFilter = (key, value) => {
    setPage(1);
    setFilters((prev) => ({
      ...prev,
      [key]: value,
    }));
  };

  const resetFilters = () => {
    setPage(1);
    setFilters({
      status: "",
      severity: "",
      source: "",
      search: "",
    });
  };

  const exportAlertsCSV = () => {
    if (!alertList.length) return;

    const headers = [
      "Type",
      "IP Address",
      "Severity",
      "Confidence",
      "Risk Score",
      "Status",
      "Source",
      "Timestamp",
    ];

    const rows = alertList.map((alert) => [
      alert.type || "-",
      alert.ip || alert.src_ip || "-",
      alert.severity || "-",
      `${Math.round(Number(alert.confidence || 0) * 100)}%`,
      alert.risk_score ?? alert.riskScore ?? "-",
      alert.status || "-",
      alert.source || "-",
      formatTimestamp(alert.timestamp),
    ]);

    const csvContent = [headers, ...rows]
      .map((row) =>
        row
          .map((field) => `"${String(field).replace(/"/g, '""')}"`)
          .join(",")
      )
      .join("\n");

    const blob = new Blob([csvContent], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `threatlens-alerts-page-${page}.csv`;
    link.click();

    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading alerts...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">
            ThreatLens / Detection / Live Alerts
          </div>

          <h1>Live Security Alerts</h1>

          <p>
            Monitor Snort events, rule-based detections, ML anomalies, collector
            health, and real-time incident signals from one professional alert
            center.
          </p>
        </div>

        <div className="command-actions">
          <button
            type="button"
            className="secondary-btn"
            onClick={() => fetchAlerts(true)}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing..." : "Refresh Alerts"}
          </button>

          <button
            type="button"
            className="primary-btn"
            onClick={exportAlertsCSV}
            disabled={!alertList.length}
          >
            Export CSV
          </button>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Socket Status</span>
          <strong>{socketState.connectionStatus}</strong>
          <small>{socketState.lastError || "Live channel active"}</small>
        </div>

        <div className="metric-card">
          <span>Collector</span>
          <strong>{collectorHeartbeat?.status || "Unknown"}</strong>
          <small>{collectorHeartbeat?.agentType || "Waiting for heartbeat"}</small>
        </div>

        <div className="metric-card">
          <span>Last Heartbeat</span>
          <strong>{formatTimestamp(collectorHeartbeat?.receivedAt)}</strong>
          <small>{collectorHeartbeat?.hostname || "No collector signal yet"}</small>
        </div>

        <div className="metric-card">
          <span>Total Alerts</span>
          <strong>{total}</strong>
          <small>Across current filter result</small>
        </div>
      </section>

      <section className="metrics-grid">
        <div className="metric-card danger">
          <span>Critical</span>
          <strong>{alertSummary.critical}</strong>
          <small>Highest priority alerts</small>
        </div>

        <div className="metric-card warning">
          <span>High Severity</span>
          <strong>{alertSummary.high}</strong>
          <small>Needs quick review</small>
        </div>

        <div className="metric-card">
          <span>Investigating</span>
          <strong>{alertSummary.investigating}</strong>
          <small>Currently under analysis</small>
        </div>

        <div className="metric-card">
          <span>Avg Confidence</span>
          <strong>{alertSummary.avgConfidence}%</strong>
          <small>Model/rule confidence</small>
        </div>

        <div className="metric-card">
          <span>Avg Risk Score</span>
          <strong>{alertSummary.avgRisk}</strong>
          <small>Calculated alert risk</small>
        </div>
      </section>

      <section className="controls alert-controls">
        <input
          className="search-input"
          type="text"
          placeholder="Search attack type, IP, keyword..."
          value={filters.search}
          onChange={(event) => updateFilter("search", event.target.value)}
        />

        <select
          value={filters.source}
          onChange={(event) => updateFilter("source", event.target.value)}
        >
          <option value="">All sources</option>
          <option value="snort">Live Snort</option>
          <option value="ids-engine-ml">ML Engine</option>
          <option value="rule-engine">Rule Engine</option>
          <option value="hids-agent">HIDS Agent</option>
          <option value="nids-collector">NIDS Collector</option>
        </select>

        <select
          value={filters.severity}
          onChange={(event) => updateFilter("severity", event.target.value)}
        >
          <option value="">All severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <select
          value={filters.status}
          onChange={(event) => updateFilter("status", event.target.value)}
        >
          <option value="">All statuses</option>
          <option value="New">New</option>
          <option value="Acknowledged">Acknowledged</option>
          <option value="Investigating">Investigating</option>
          <option value="Resolved">Resolved</option>
          <option value="False Positive">False Positive</option>
        </select>

        {hasActiveFilters && (
          <button type="button" className="secondary-btn" onClick={resetFilters}>
            Clear Filters
          </button>
        )}
      </section>

      <section className="card alert-card">
        <div className="card-header">
          <div>
            <h2>Alert Queue</h2>
            <p>
              Showing {alertList.length} of {total} alerts
            </p>
          </div>

          <span className="live-badge">
            {socketState.connectionStatus === "connected"
              ? "Live monitoring active"
              : "Live channel inactive"}
          </span>
        </div>

        {alertList.length > 0 ? (
          <>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Alert Type</th>
                    <th>IP Address</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Risk</th>
                    <th>Status</th>
                    <th>Source</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>

                <tbody>
                  {alertList.map((alert) => {
                    const ip = alert.ip || alert.src_ip || alert.source_ip || "-";
                    const risk = alert.risk_score ?? alert.riskScore ?? 50;
                    const confidence = Math.round(Number(alert.confidence || 0) * 100);

                    return (
                      <tr key={alert._id}>
                        <td>
                          <Link to={`/alerts/${alert._id}`} className="alert-link">
                            {alert.type || alert.title || "Unknown Alert"}
                          </Link>
                          <small className="table-subtext">
                            {alert.description || alert.message || "No description"}
                          </small>
                        </td>

                        <td className="ip-cell">{ip}</td>

                        <td>
                          <span
                            className={`severity ${getSeverityClass(alert.severity)}`}
                          >
                            {alert.severity || "Unknown"}
                          </span>
                        </td>

                        <td>{confidence}%</td>

                        <td>
                          <span className="risk-score">{risk}</span>
                        </td>

                        <td>{alert.status || "New"}</td>

                        <td>{alert.source || "ThreatLens"}</td>

                        <td>{formatTimestamp(alert.timestamp)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="pagination">
              <button
                type="button"
                onClick={() => setPage((current) => Math.max(current - 1, 1))}
                disabled={page === 1}
              >
                Previous
              </button>

              <span>
                Page {page} of {totalPages}
              </span>

              <button
                type="button"
                onClick={() =>
                  setPage((current) => Math.min(current + 1, totalPages))
                }
                disabled={page >= totalPages}
              >
                Next
              </button>
            </div>
          </>
        ) : (
          <div className="empty-state">
            <h3>No alerts detected yet</h3>
            <p>
              Once Snort, HIDS agent, rule engine, or ML service sends suspicious
              activity, alerts will appear here automatically.
            </p>
          </div>
        )}
      </section>
    </MainLayout>
  );
};

export default Alerts;