import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";
import useSocket from "../hooks/useSocket";

const resolveSocketAlert = (payload) => payload?.data || payload;

const formatTimestamp = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const Alerts = () => {
  const [alertList, setAlertList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [collectorHeartbeat, setCollectorHeartbeat] = useState(null);
  const [filters, setFilters] = useState({
    status: "",
    severity: "",
    search: "",
    source: "",
  });

  const limit = 20;
  const token = localStorage.getItem("accessToken");
  const abortRef = useRef(null);
  const isMountedRef = useRef(true);
  const refreshTimerRef = useRef(null);
  const alertListRef = useRef([]);

  useEffect(() => {
    alertListRef.current = alertList;
  }, [alertList]);

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

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(fetchAlerts, 300);
  }, [fetchAlerts]);

  const hasActiveFilters = useMemo(
    () => Object.values(filters).some((value) => String(value || "").trim() !== ""),
    [filters]
  );

  const mergeIncomingAlert = useCallback((incoming, prepend = false) => {
    if (!incoming?._id) {
      scheduleRefresh();
      return;
    }

    const exists = alertListRef.current.some((item) => item._id === incoming._id);

    setAlertList((current) => {
      const next = current.map((item) => (item._id === incoming._id ? { ...item, ...incoming } : item));
      if (exists) {
        return prepend ? next.sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp)) : next;
      }

      const merged = prepend ? [incoming, ...next] : [...next, incoming];
      return merged.slice(0, limit);
    });

    if (!exists) {
      setTotal((current) => current + 1);
    }
  }, [limit, scheduleRefresh]);

  const socketState = useSocket(
    token,
    useMemo(
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
      [hasActiveFilters, mergeIncomingAlert, page, scheduleRefresh]
    )
  );

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
      investigating: totals.investigating,
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
          <h1>Live Snort Alerts</h1>
          <p>
            Real-time intrusion alerts generated from live Snort events, correlation rules, and the connected ML analysis pipeline.
          </p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Socket</span>
          <strong>{socketState.connectionStatus}</strong>
          <small>{socketState.lastError || "Live channel status"}</small>
        </div>
        <div className="metric-card">
          <span>Collector</span>
          <strong>{collectorHeartbeat?.status || "unknown"}</strong>
          <small>{collectorHeartbeat?.agentType || "Waiting for heartbeat"}</small>
        </div>
        <div className="metric-card">
          <span>Last Heartbeat</span>
          <strong>{formatTimestamp(collectorHeartbeat?.receivedAt)}</strong>
          <small>{collectorHeartbeat?.hostname || "No collector signal yet"}</small>
        </div>
      </section>

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
          <option value="">All alert sources</option>
          <option value="snort">Live Snort</option>
          <option value="ids-engine-ml">ML Anomalies</option>
          <option value="rule-engine">Rule Engine</option>
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
                    <td>{alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <button onClick={() => setPage((p) => Math.max(p - 1, 1))} disabled={page === 1}>
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
          <p>No alerts detected yet.</p>
        )}
      </div>
    </MainLayout>
  );
};

export default Alerts;
