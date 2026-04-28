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

const getStatusClass = (status = "") => {
  switch (String(status).toLowerCase()) {
    case "resolved":
      return "status-resolved";
    case "investigating":
      return "status-investigating";
    case "acknowledged":
      return "status-acknowledged";
    case "false positive":
      return "status-false";
    default:
      return "status-new";
  }
};

const getAlertTitle = (alert) =>
  alert.type ||
  alert.title ||
  alert.attack_type ||
  alert.attackType ||
  alert.event_type ||
  alert.eventType ||
  "Unknown Alert";

const getAlertIp = (alert) =>
  alert.ip ||
  alert.src_ip ||
  alert.source_ip ||
  alert.srcIp ||
  alert.sourceIp ||
  alert.remoteAddress ||
  alert.metadata?.src_ip ||
  alert.metadata?.source_ip ||
  "-";

const getAlertRisk = (alert) => {
  const risk = Number(alert.risk_score ?? alert.riskScore ?? alert.score ?? 50);
  return Number.isNaN(risk) ? 50 : risk;
};

const getAlertConfidence = (alert) => {
  const value = Number(alert.confidence ?? alert.ml_confidence ?? alert.mlConfidence ?? 0);
  if (Number.isNaN(value)) return 0;
  return value <= 1 ? Math.round(value * 100) : Math.round(value);
};

const Alerts = () => {
  const [alertList, setAlertList] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
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

  const hasActiveFilters = useMemo(
    () => Object.values(filters).some((value) => String(value || "").trim() !== ""),
    [filters]
  );

  const fetchAlerts = useCallback(
    async (silent = false) => {
      try {
        silent ? setRefreshing(true) : setLoading(true);
        setError("");

        const response = await alerts.list(LIMIT, page, filters);
        const data = response?.data?.data || [];
        const pagination = response?.data?.pagination || {};

        if (!isMountedRef.current) return;

        setAlertList(Array.isArray(data) ? data : []);
        setTotal(pagination.total ?? data.length ?? 0);
      } catch (err) {
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

        const merged = exists
          ? updated
          : prepend
          ? [incoming, ...updated]
          : [...updated, incoming];

        return merged
          .sort((a, b) => new Date(b.timestamp || b.createdAt || 0) - new Date(a.timestamp || a.createdAt || 0))
          .slice(0, LIMIT);
      });

      if (!exists) setTotal((current) => current + 1);
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

        mergeIncomingAlert(incoming);
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
      if (summary[severity] !== undefined) summary[severity] += 1;

      if (String(alert.status || "New").toLowerCase() === "investigating") {
        summary.investigating += 1;
      }

      confidenceTotal += getAlertConfidence(alert);
      riskTotal += getAlertRisk(alert);
    });

    summary.avgConfidence = Math.round(confidenceTotal / alertList.length);
    summary.avgRisk = Math.round(riskTotal / alertList.length);

    return summary;
  }, [alertList]);

  const totalPages = Math.max(1, Math.ceil(total / LIMIT));

  const updateFilter = (key, value) => {
    setPage(1);
    setFilters((prev) => ({ ...prev, [key]: value }));
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
      "Alert Type",
      "IP Address",
      "Severity",
      "Confidence",
      "Risk Score",
      "Status",
      "Source",
      "Timestamp",
      "Description",
    ];

    const rows = alertList.map((alert) => [
      getAlertTitle(alert),
      getAlertIp(alert),
      alert.severity || "-",
      `${getAlertConfidence(alert)}%`,
      getAlertRisk(alert),
      alert.status || "New",
      alert.source || "ThreatLens",
      formatTimestamp(alert.timestamp || alert.createdAt),
      alert.description || alert.message || "-",
    ]);

    const csvContent = [headers, ...rows]
      .map((row) =>
        row.map((field) => `"${String(field).replace(/"/g, '""')}"`).join(",")
      )
      .join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
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
        <div className="loading">Loading live alerts...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <style>{`
        .alerts-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background: linear-gradient(135deg, #fff7ed 0%, #f8fbff 55%, #eef9f1 100%);
        }

        .alerts-shell {
          max-width: 1240px;
          margin: 0 auto;
        }

        .alerts-header {
          display: flex;
          justify-content: space-between;
          gap: 22px;
          align-items: flex-start;
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 24px;
          padding: 30px;
          margin-bottom: 24px;
          box-shadow: 0 18px 45px rgba(15,23,42,.08);
        }

        .alerts-eyebrow {
          font-size: 12px;
          font-weight: 900;
          color: #0ea5e9;
          text-transform: uppercase;
          letter-spacing: .12em;
          margin-bottom: 8px;
        }

        .alerts-header h1 {
          margin: 0;
          font-size: 34px;
          color: #0f2742;
        }

        .alerts-header p {
          margin: 10px 0 0;
          color: #64748b;
          line-height: 1.6;
          max-width: 760px;
        }

        .alerts-actions {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          justify-content: flex-end;
        }

        .primary-btn,
        .secondary-btn {
          border: 0;
          border-radius: 14px;
          padding: 13px 18px;
          font-weight: 900;
          cursor: pointer;
          transition: .2s ease;
          white-space: nowrap;
        }

        .primary-btn {
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
          color: #fff;
          box-shadow: 0 12px 26px rgba(37,99,235,.22);
        }

        .secondary-btn {
          background: #eef6ff;
          color: #0f2742;
          border: 1px solid #dbeafe;
        }

        .primary-btn:hover,
        .secondary-btn:hover {
          transform: translateY(-1px);
        }

        .primary-btn:disabled,
        .secondary-btn:disabled {
          opacity: .6;
          cursor: not-allowed;
          transform: none;
        }

        .alerts-metrics {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 18px;
          margin-bottom: 22px;
        }

        .alert-metric-card {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 20px;
          padding: 22px;
          box-shadow: 0 14px 34px rgba(15,23,42,.07);
        }

        .alert-metric-card span {
          display: block;
          font-size: 12px;
          color: #64748b;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: .08em;
          margin-bottom: 10px;
        }

        .alert-metric-card strong {
          display: block;
          font-size: 28px;
          color: #0f2742;
          margin-bottom: 6px;
        }

        .alert-metric-card small {
          color: #64748b;
        }

        .alert-metric-card.danger strong {
          color: #dc2626;
        }

        .alert-metric-card.warning strong {
          color: #ea580c;
        }

        .alerts-controls {
          display: grid;
          grid-template-columns: 2fr 1fr 1fr 1fr auto;
          gap: 14px;
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 20px;
          padding: 18px;
          margin-bottom: 22px;
          box-shadow: 0 14px 34px rgba(15,23,42,.06);
        }

        .alerts-controls input,
        .alerts-controls select {
          width: 100%;
          border: 1px solid #dbe3ef;
          background: #f8fbff;
          border-radius: 14px;
          padding: 13px 14px;
          outline: none;
          color: #172033;
          font-size: 14px;
        }

        .alerts-controls input:focus,
        .alerts-controls select:focus {
          border-color: #0ea5e9;
          box-shadow: 0 0 0 4px rgba(14,165,233,.12);
          background: #fff;
        }

        .alerts-card {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 24px;
          box-shadow: 0 18px 45px rgba(15,23,42,.08);
          overflow: hidden;
        }

        .alerts-card-header {
          padding: 24px 26px;
          border-bottom: 1px solid #eef2f7;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 18px;
        }

        .alerts-card-header h2 {
          margin: 0;
          color: #172033;
        }

        .alerts-card-header p {
          margin: 6px 0 0;
          color: #64748b;
        }

        .live-badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 9px 14px;
          border-radius: 999px;
          color: #047857;
          background: #ecfdf5;
          border: 1px solid #bbf7d0;
          font-size: 12px;
          font-weight: 900;
        }

        .live-badge::before {
          content: "";
          width: 9px;
          height: 9px;
          border-radius: 99px;
          background: #22c55e;
        }

        .live-badge.muted {
          color: #991b1b;
          background: #fff1f2;
          border-color: #fecdd3;
        }

        .live-badge.muted::before {
          background: #ef4444;
        }

        .alerts-table-wrapper {
          overflow-x: auto;
        }

        .alerts-table {
          width: 100%;
          border-collapse: collapse;
          min-width: 1050px;
        }

        .alerts-table th,
        .alerts-table td {
          text-align: left;
          padding: 17px 18px;
          border-bottom: 1px solid #eef2f7;
          vertical-align: top;
        }

        .alerts-table th {
          background: #f8fbff;
          color: #475569;
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: .08em;
        }

        .alerts-table td {
          color: #172033;
          font-size: 14px;
        }

        .alert-link {
          display: inline-block;
          color: #0f2742;
          font-weight: 900;
          text-decoration: none;
          margin-bottom: 6px;
        }

        .alert-link:hover {
          color: #2563eb;
        }

        .table-subtext {
          display: block;
          color: #64748b;
          line-height: 1.5;
          max-width: 360px;
        }

        .ip-cell {
          font-family: Consolas, monospace;
          font-weight: 800;
        }

        .severity,
        .status-pill {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          padding: 7px 11px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 900;
          white-space: nowrap;
        }

        .severity-critical {
          background: #fee2e2;
          color: #991b1b;
        }

        .severity-high {
          background: #ffedd5;
          color: #9a3412;
        }

        .severity-medium {
          background: #fef9c3;
          color: #854d0e;
        }

        .severity-low {
          background: #dcfce7;
          color: #166534;
        }

        .severity-unknown {
          background: #e2e8f0;
          color: #475569;
        }

        .status-new {
          background: #eff6ff;
          color: #1d4ed8;
        }

        .status-acknowledged {
          background: #f5f3ff;
          color: #6d28d9;
        }

        .status-investigating {
          background: #fff7ed;
          color: #c2410c;
        }

        .status-resolved {
          background: #ecfdf5;
          color: #047857;
        }

        .status-false {
          background: #f1f5f9;
          color: #475569;
        }

        .confidence-cell {
          min-width: 120px;
        }

        .confidence-cell span {
          font-weight: 900;
          color: #0f2742;
        }

        .confidence-track {
          height: 8px;
          border-radius: 999px;
          background: #e2e8f0;
          overflow: hidden;
          margin-top: 7px;
        }

        .confidence-fill {
          height: 100%;
          border-radius: 999px;
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
        }

        .risk-score {
          font-weight: 900;
          color: #dc2626;
        }

        .pagination {
          padding: 20px 26px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 14px;
          flex-wrap: wrap;
        }

        .pagination button {
          border: 1px solid #dbeafe;
          background: #eef6ff;
          color: #0f2742;
          border-radius: 12px;
          padding: 11px 16px;
          font-weight: 900;
          cursor: pointer;
        }

        .pagination button:disabled {
          opacity: .45;
          cursor: not-allowed;
        }

        .empty-state {
          text-align: center;
          padding: 60px 24px;
        }

        .empty-state h3 {
          margin: 0 0 8px;
          color: #172033;
        }

        .empty-state p {
          margin: 0 auto 20px;
          color: #64748b;
          max-width: 520px;
          line-height: 1.6;
        }

        .error-message {
          background: #fff1f2;
          color: #be123c;
          border: 1px solid #fecdd3;
          border-radius: 14px;
          padding: 14px 16px;
          margin-bottom: 18px;
          font-weight: 800;
        }

        .alert-details-panel {
          margin-top: 22px;
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 22px;
          padding: 24px;
          box-shadow: 0 14px 34px rgba(15,23,42,.07);
        }

        .alert-details-panel h3 {
          margin: 0 0 12px;
          color: #172033;
        }

        .details-grid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 14px;
        }

        .detail-box {
          background: #f8fbff;
          border: 1px solid #e2e8f0;
          border-radius: 16px;
          padding: 15px;
        }

        .detail-box span {
          display: block;
          color: #64748b;
          font-size: 12px;
          font-weight: 900;
          margin-bottom: 6px;
        }

        .detail-box strong {
          color: #0f2742;
          overflow-wrap: anywhere;
        }

        @media (max-width: 1100px) {
          .alerts-metrics {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .alerts-controls {
            grid-template-columns: 1fr 1fr;
          }

          .details-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }

        @media (max-width: 720px) {
          .alerts-page {
            padding: 16px;
          }

          .alerts-header {
            flex-direction: column;
            padding: 24px;
          }

          .alerts-header h1 {
            font-size: 28px;
          }

          .alerts-actions,
          .primary-btn,
          .secondary-btn {
            width: 100%;
          }

          .alerts-metrics,
          .alerts-controls,
          .details-grid {
            grid-template-columns: 1fr;
          }

          .alerts-card-header {
            flex-direction: column;
            align-items: flex-start;
          }
        }
      `}</style>

      <div className="alerts-page">
        <div className="alerts-shell">
          <section className="alerts-header">
            <div>
              <div className="alerts-eyebrow">ThreatLens / Detection Center</div>
              <h1>Live Security Alerts</h1>
              <p>
                Monitor Snort events, HIDS signals, ML detections, rule-based alerts,
                and real-time collector health from one professional alert center.
              </p>
            </div>

            <div className="alerts-actions">
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

          <section className="alerts-metrics">
            <div className="alert-metric-card">
              <span>Live Channel</span>
              <strong>{socketState.connectionStatus}</strong>
              <small>{socketState.lastError || "Socket listener ready"}</small>
            </div>

            <div className="alert-metric-card">
              <span>Collector</span>
              <strong>{collectorHeartbeat?.status || "Unknown"}</strong>
              <small>{collectorHeartbeat?.agentType || "Waiting for heartbeat"}</small>
            </div>

            <div className="alert-metric-card">
              <span>Total Alerts</span>
              <strong>{total}</strong>
              <small>Current filtered result</small>
            </div>

            <div className="alert-metric-card danger">
              <span>Critical</span>
              <strong>{alertSummary.critical}</strong>
              <small>Immediate action required</small>
            </div>

            <div className="alert-metric-card warning">
              <span>High</span>
              <strong>{alertSummary.high}</strong>
              <small>Needs quick review</small>
            </div>

            <div className="alert-metric-card">
              <span>Investigating</span>
              <strong>{alertSummary.investigating}</strong>
              <small>Active analyst workflow</small>
            </div>

            <div className="alert-metric-card">
              <span>Avg Confidence</span>
              <strong>{alertSummary.avgConfidence}%</strong>
              <small>Rule / ML certainty</small>
            </div>

            <div className="alert-metric-card">
              <span>Avg Risk</span>
              <strong>{alertSummary.avgRisk}</strong>
              <small>Calculated threat score</small>
            </div>
          </section>

          <section className="alerts-controls">
            <input
              type="text"
              placeholder="Search attack type, IP, source, keyword..."
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

          <section className="alerts-card">
            <div className="alerts-card-header">
              <div>
                <h2>Alert Queue</h2>
                <p>
                  Showing {alertList.length} of {total} alerts
                </p>
              </div>

              <span
                className={
                  socketState.connectionStatus === "connected"
                    ? "live-badge"
                    : "live-badge muted"
                }
              >
                {socketState.connectionStatus === "connected"
                  ? "Live monitoring active"
                  : "Live channel inactive"}
              </span>
            </div>

            {alertList.length > 0 ? (
              <>
                <div className="alerts-table-wrapper">
                  <table className="alerts-table">
                    <thead>
                      <tr>
                        <th>Alert</th>
                        <th>IP Address</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Risk</th>
                        <th>Status</th>
                        <th>Source</th>
                        <th>Timestamp</th>
                        <th>Inspect</th>
                      </tr>
                    </thead>

                    <tbody>
                      {alertList.map((alert) => {
                        const title = getAlertTitle(alert);
                        const ip = getAlertIp(alert);
                        const risk = getAlertRisk(alert);
                        const confidence = getAlertConfidence(alert);
                        const status = alert.status || "New";

                        return (
                          <tr key={alert._id}>
                            <td>
                              <Link to={`/alerts/${alert._id}`} className="alert-link">
                                {title}
                              </Link>

                              <small className="table-subtext">
                                {alert.description ||
                                  alert.message ||
                                  "No additional alert description available."}
                              </small>
                            </td>

                            <td className="ip-cell">{ip}</td>

                            <td>
                              <span className={`severity ${getSeverityClass(alert.severity)}`}>
                                {alert.severity || "Unknown"}
                              </span>
                            </td>

                            <td>
                              <div className="confidence-cell">
                                <span>{confidence}%</span>
                                <div className="confidence-track">
                                  <div
                                    className="confidence-fill"
                                    style={{ width: `${Math.min(confidence, 100)}%` }}
                                  />
                                </div>
                              </div>
                            </td>

                            <td>
                              <span className="risk-score">{risk}</span>
                            </td>

                            <td>
                              <span className={`status-pill ${getStatusClass(status)}`}>
                                {status}
                              </span>
                            </td>

                            <td>{alert.source || "ThreatLens"}</td>

                            <td>{formatTimestamp(alert.timestamp || alert.createdAt)}</td>

                            <td>
                              <button
                                type="button"
                                className="secondary-btn"
                                onClick={() => setSelectedAlert(alert)}
                              >
                                View
                              </button>
                            </td>
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
                    onClick={() => setPage((current) => Math.min(current + 1, totalPages))}
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

                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => fetchAlerts(true)}
                  disabled={refreshing}
                >
                  Check Again
                </button>
              </div>
            )}
          </section>

          {selectedAlert && (
            <section className="alert-details-panel">
              <h3>Selected Alert Details</h3>

              <div className="details-grid">
                <div className="detail-box">
                  <span>Attack Type</span>
                  <strong>{getAlertTitle(selectedAlert)}</strong>
                </div>

                <div className="detail-box">
                  <span>Source IP</span>
                  <strong>{getAlertIp(selectedAlert)}</strong>
                </div>

                <div className="detail-box">
                  <span>Severity</span>
                  <strong>{selectedAlert.severity || "Unknown"}</strong>
                </div>

                <div className="detail-box">
                  <span>Status</span>
                  <strong>{selectedAlert.status || "New"}</strong>
                </div>

                <div className="detail-box">
                  <span>Confidence</span>
                  <strong>{getAlertConfidence(selectedAlert)}%</strong>
                </div>

                <div className="detail-box">
                  <span>Risk Score</span>
                  <strong>{getAlertRisk(selectedAlert)}</strong>
                </div>

                <div className="detail-box">
                  <span>Source</span>
                  <strong>{selectedAlert.source || "ThreatLens"}</strong>
                </div>

                <div className="detail-box">
                  <span>Timestamp</span>
                  <strong>{formatTimestamp(selectedAlert.timestamp || selectedAlert.createdAt)}</strong>
                </div>
              </div>
            </section>
          )}
        </div>
      </div>
    </MainLayout>
  );
};

export default Alerts;