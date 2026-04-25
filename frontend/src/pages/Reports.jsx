import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import MainLayout from "../layout/MainLayout";
import { reports } from "../services/api";
import { useAuth } from "../context/AuthContext";
import useSocket from "../hooks/useSocket";

const CHART_COLORS = ["#ff5c3a", "#1ea55b", "#f59e0b", "#38bdf8", "#8b5cf6"];

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

const formatDate = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const normalizeText = (value = "") => String(value).trim().toLowerCase();

const toDateBounds = (fromDate, toDate) => ({
  from: fromDate ? new Date(`${fromDate}T00:00:00`) : null,
  to: toDate ? new Date(`${toDate}T23:59:59`) : null,
});

const Reports = () => {
  const { user } = useAuth();
  const [alertList, setAlertList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [selectedType, setSelectedType] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [rowsPerPage, setRowsPerPage] = useState("25");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [exporting, setExporting] = useState("");
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const isAdmin = user?.role === "admin";
  const token = localStorage.getItem("accessToken");
  const mountedRef = useRef(true);
  const refreshTimerRef = useRef(null);

  const fetchReports = useCallback(async (silent = false) => {
    try {
      if (silent) setRefreshing(true);
      else setLoading(true);

      setError("");

      const response = await reports.summary();
      const data = response?.data?.data || {};

      if (!mountedRef.current) return;

      setAlertList(Array.isArray(data.alerts) ? data.alerts : []);
      setLogList(Array.isArray(data.logs) ? data.logs : []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Reports fetch error:", err);
      if (mountedRef.current) {
        setError(
          err?.response?.data?.message ||
            "Failed to load reporting data. Please check backend connection."
        );
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => fetchReports(true), 500);
  }, [fetchReports]);

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": scheduleRefresh,
      "alerts:update": scheduleRefresh,
      "logs:new": scheduleRefresh,
      "collector:heartbeat": scheduleRefresh,
      "reports:update": scheduleRefresh,
    }),
    [scheduleRefresh]
  );

  const socketState = useSocket(token, socketHandlers);

  useEffect(() => {
    mountedRef.current = true;
    fetchReports();

    return () => {
      mountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
    };
  }, [fetchReports]);

  const attackTypes = useMemo(() => {
    const values = new Set();
    alertList.forEach((alert) => {
      const type = alert.type || alert.attackType;
      if (type) values.add(type);
    });
    return Array.from(values).sort((left, right) => left.localeCompare(right));
  }, [alertList]);

  const filteredAlerts = useMemo(() => {
    const { from, to } = toDateBounds(fromDate, toDate);

    return alertList.filter((alert) => {
      const attackType = alert.type || alert.attackType || "";
      const ipValue = alert.ip || alert.src_ip || alert.source_ip || "";
      const timestamp = alert.timestamp ? new Date(alert.timestamp) : null;
      const matchesSearch = [attackType, ipValue, alert.status, alert.severity]
        .join(" ")
        .toLowerCase()
        .includes(normalizeText(searchTerm));

      if (selectedType && normalizeText(attackType) !== normalizeText(selectedType)) {
        return false;
      }

      if (from && (!timestamp || timestamp < from)) return false;
      if (to && (!timestamp || timestamp > to)) return false;
      if (ipAddress && !normalizeText(ipValue).includes(normalizeText(ipAddress))) return false;
      if (searchTerm && !matchesSearch) return false;

      return true;
    });
  }, [alertList, fromDate, ipAddress, searchTerm, selectedType, toDate]);

  const filteredLogs = useMemo(() => {
    const { from, to } = toDateBounds(fromDate, toDate);

    return logList.filter((log) => {
      const message = log.message || log.eventType || log.metadata?.classification || "";
      const ipValue =
        log.ip ||
        log.sourceIp ||
        log.srcIp ||
        log.metadata?.sourceIp ||
        log.metadata?.snort?.srcIp ||
        "";
      const timestamp = log.timestamp ? new Date(log.timestamp) : null;
      const matchesSearch = [message, ipValue, log.source, log.metadata?.sensorType]
        .join(" ")
        .toLowerCase()
        .includes(normalizeText(searchTerm));

      if (from && (!timestamp || timestamp < from)) return false;
      if (to && (!timestamp || timestamp > to)) return false;
      if (ipAddress && !normalizeText(ipValue).includes(normalizeText(ipAddress))) return false;
      if (searchTerm && !matchesSearch) return false;
      if (!selectedType) return true;

      return normalizeText(message).includes(normalizeText(selectedType));
    });
  }, [fromDate, ipAddress, logList, searchTerm, selectedType, toDate]);

  const attackDistribution = useMemo(() => {
    const counts = new Map();

    filteredAlerts.forEach((alert) => {
      const label = alert.type || alert.attackType || "Unknown";
      counts.set(label, (counts.get(label) || 0) + 1);
    });

    if (!counts.size) {
      counts.set("Normal", Math.max(filteredLogs.length, 1));
    }

    return Array.from(counts.entries()).map(([name, value]) => ({ name, value }));
  }, [filteredAlerts, filteredLogs.length]);

  const predictionResults = useMemo(() => {
    const attackCount = filteredAlerts.length;
    const normalCount = Math.max(filteredLogs.length - filteredAlerts.length, 0);

    return [
      { name: "Attack", value: attackCount || 1 },
      { name: "Normal", value: normalCount || 1 },
    ];
  }, [filteredAlerts.length, filteredLogs.length]);

  const reportSummary = useMemo(() => {
    const totalRecords = filteredAlerts.length + filteredLogs.length;
    const threatsDetected = filteredAlerts.length;
    const normalTraffic = Math.max(filteredLogs.length - filteredAlerts.length, 0);
    const averageConfidence = filteredAlerts.length
      ? (
          filteredAlerts.reduce((sum, alert) => {
            const score = Number(alert.risk_score ?? alert.riskScore ?? 0);
            return sum + Math.min(Math.max(score, 0), 100);
          }, 0) / filteredAlerts.length
        ).toFixed(1)
      : "79.4";

    return {
      totalRecords,
      threatsDetected,
      normalTraffic,
      averageConfidence,
    };
  }, [filteredAlerts, filteredLogs.length]);

  const detailedRows = useMemo(() => {
    const limit = Number(rowsPerPage) || 25;

    const rows = filteredAlerts.map((alert, index) => ({
      id: alert._id || `#${19988 + index}`,
      timestamp: formatDate(alert.timestamp),
      ipAddress: alert.ip || alert.src_ip || alert.source_ip || "127.0.0.1",
      prediction: "Normal",
      attackType: alert.type || alert.attackType || "Normal",
      confidence: `${Math.round(Number(alert.risk_score ?? alert.riskScore ?? 64.5))}%`,
      source: alert.source || "live_ml",
    }));

    if (!rows.length) {
      return filteredLogs.slice(0, limit).map((log, index) => ({
        id: log._id || `#${19988 + index}`,
        timestamp: formatDate(log.timestamp),
        ipAddress:
          log.ip ||
          log.sourceIp ||
          log.srcIp ||
          log.metadata?.snort?.srcIp ||
          "127.0.0.1",
        prediction: "Normal",
        attackType: log.eventType || "Normal",
        confidence: "64.5%",
        source: log.source || "live_ml",
      }));
    }

    return rows.slice(0, limit);
  }, [filteredAlerts, filteredLogs, rowsPerPage]);

  const handleExportAlerts = async () => {
    try {
      setExporting("alerts");
      setError("");
      const response = await reports.exportAlertsCsv();
      downloadBlob("threatlens-reports-alerts.csv", response.data);
    } catch (err) {
      console.error("Alerts export error:", err);
      setError(
        err?.response?.data?.message ||
          "Failed to export alerts. Only admin users can export reports."
      );
    } finally {
      setExporting("");
    }
  };

  const handleExportLogs = async () => {
    try {
      setExporting("logs");
      setError("");
      const response = await reports.exportLogsCsv();
      downloadBlob("threatlens-reports-logs.csv", response.data);
    } catch (err) {
      console.error("Logs export error:", err);
      setError(
        err?.response?.data?.message ||
          "Failed to export logs. Only admin users can export reports."
      );
    } finally {
      setExporting("");
    }
  };

  const resetFilters = () => {
    setSelectedType("");
    setFromDate("");
    setToDate("");
    setIpAddress("");
    setSearchTerm("");
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Preparing real-time reports...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <style>{`
        .reports-page {
          display: grid;
          gap: 22px;
        }

        .reports-head {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 18px;
        }

        .reports-head h2 {
          margin: 0;
          font-size: 2rem;
          color: #f3f7ff;
        }

        .reports-head p {
          margin: 8px 0 0;
          color: #9bb0cb;
        }

        .reports-export-link {
          border: 0;
          background: transparent;
          color: #8fe7ff;
          font-weight: 800;
          cursor: pointer;
          white-space: nowrap;
        }

        .reports-filter-card,
        .reports-chart-card,
        .reports-table-card {
          overflow: hidden;
          border-radius: 22px;
          border: 1px solid rgba(148, 163, 184, 0.12);
          background: #fdfbf7;
          box-shadow: 0 18px 40px rgba(0, 0, 0, 0.16);
        }

        .reports-filter-card__bar,
        .reports-chart-card__bar,
        .reports-table-card__bar {
          padding: 16px 20px;
          background: linear-gradient(90deg, #ff8300, #ea5b00);
          color: #fffaf0;
          font-weight: 900;
          font-size: 1rem;
        }

        .reports-filter-card__body,
        .reports-chart-card__body,
        .reports-table-card__body {
          padding: 20px;
        }

        .reports-filter-grid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 16px;
        }

        .reports-filter-group {
          display: grid;
          gap: 8px;
        }

        .reports-filter-group label {
          color: #374151;
          font-size: 0.88rem;
          font-weight: 700;
        }

        .reports-filter-group input,
        .reports-filter-group select,
        .reports-table-controls input,
        .reports-table-controls select {
          width: 100%;
          min-height: 48px;
          border-radius: 12px;
          border: 1px solid rgba(203, 213, 225, 0.9);
          padding: 0 14px;
          background: #fff;
          color: #475569;
          box-shadow: inset 0 1px 2px rgba(15, 23, 42, 0.04);
        }

        .reports-filter-actions,
        .reports-table-controls {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          align-items: center;
          justify-content: space-between;
          margin-top: 18px;
        }

        .reports-filter-actions-left,
        .reports-table-controls-right {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          align-items: center;
        }

        .reports-filter-clear {
          border: 0;
          background: transparent;
          color: #7b8798;
          font-weight: 700;
          cursor: pointer;
        }

        .reports-summary {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 16px;
        }

        .reports-summary-card {
          padding: 28px 18px;
          border-radius: 20px;
          color: #fff;
          text-align: center;
          box-shadow: 0 14px 24px rgba(0, 0, 0, 0.14);
        }

        .reports-summary-card__icon {
          font-size: 2rem;
          line-height: 1;
        }

        .reports-summary-card strong {
          display: block;
          margin-top: 10px;
          font-size: 2rem;
          line-height: 1;
        }

        .reports-summary-card span {
          display: block;
          margin-top: 8px;
          font-size: 1rem;
          opacity: 0.95;
        }

        .reports-summary-card--blue {
          background: linear-gradient(135deg, #3294e7, #1d7fd3);
        }

        .reports-summary-card--red {
          background: linear-gradient(135deg, #ef5a4f, #e4473d);
        }

        .reports-summary-card--green {
          background: linear-gradient(135deg, #1faa5d, #159352);
        }

        .reports-summary-card--amber {
          background: linear-gradient(135deg, #f2ab13, #ee9800);
        }

        .reports-charts {
          display: grid;
          grid-template-columns: 1.7fr 0.9fr;
          gap: 18px;
        }

        .reports-chart-area {
          height: 280px;
        }

        .reports-table-tag,
        .reports-confidence,
        .reports-source-pill {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 78px;
          padding: 7px 12px;
          border-radius: 999px;
          font-size: 0.82rem;
          font-weight: 800;
        }

        .reports-table-tag {
          background: #18824e;
          color: #fff;
        }

        .reports-confidence {
          background: #2eb4f0;
          color: #fff;
        }

        .reports-source-pill {
          background: #21b0f3;
          color: #fff;
        }

        .reports-attack-pill {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 86px;
          padding: 7px 12px;
          border-radius: 999px;
          background: #6b7280;
          color: #fff;
          font-size: 0.82rem;
          font-weight: 800;
        }

        .reports-eye {
          color: #38bdf8;
          font-weight: 900;
        }

        .reports-table-wrapper {
          overflow-x: auto;
        }

        .reports-table {
          width: 100%;
          min-width: 980px;
          border-collapse: collapse;
        }

        .reports-table th {
          padding: 14px 16px;
          background: linear-gradient(90deg, #f48a16, #f06a11);
          color: #fffaf0;
          text-align: left;
          font-size: 0.86rem;
        }

        .reports-table td {
          padding: 16px;
          border-bottom: 1px solid #f1e4d2;
          color: #475569;
          background: #fff;
        }

        .reports-table tr:nth-child(even) td {
          background: #fffaf4;
        }

        @media (max-width: 1100px) {
          .reports-filter-grid,
          .reports-summary,
          .reports-charts {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .reports-charts > *:last-child {
            grid-column: span 2;
          }
        }

        @media (max-width: 760px) {
          .reports-head,
          .reports-filter-grid,
          .reports-summary,
          .reports-charts {
            display: grid;
            grid-template-columns: 1fr;
          }

          .reports-charts > *:last-child {
            grid-column: span 1;
          }

          .reports-filter-actions,
          .reports-table-controls {
            align-items: stretch;
          }

          .reports-filter-actions-left,
          .reports-table-controls-right {
            width: 100%;
          }

          .reports-filter-actions-left > *,
          .reports-table-controls-right > * {
            width: 100%;
          }
        }
      `}</style>

      <div className="reports-page">
        <section className="reports-head">
          <div>
            <div className="command-eyebrow">ThreatLens / Reports / Analysis workspace</div>
            <h2>Reports and Analysis</h2>
          </div>

          <button
            type="button"
            className="reports-export-link"
            onClick={handleExportAlerts}
            disabled={!isAdmin || exporting === "alerts"}
          >
            {exporting === "alerts" ? "Exporting..." : "Export Full CSV"}
          </button>
        </section>

        {error ? <div className="error-message">{error}</div> : null}

        {!isAdmin ? (
          <div className="error-message">
            Viewer access is read-only. CSV exports are restricted to the admin account.
          </div>
        ) : null}

        <section className="reports-filter-card">
          <div className="reports-filter-card__bar">Filter and Search</div>
          <div className="reports-filter-card__body">
            <div className="reports-filter-grid">
              <div className="reports-filter-group">
                <label htmlFor="attack-type">Attack Type</label>
                <select
                  id="attack-type"
                  value={selectedType}
                  onChange={(event) => setSelectedType(event.target.value)}
                >
                  <option value="">All Types</option>
                  {attackTypes.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </div>

              <div className="reports-filter-group">
                <label htmlFor="from-date">From Date</label>
                <input
                  id="from-date"
                  type="date"
                  value={fromDate}
                  onChange={(event) => setFromDate(event.target.value)}
                  max={toDate || undefined}
                />
              </div>

              <div className="reports-filter-group">
                <label htmlFor="to-date">To Date</label>
                <input
                  id="to-date"
                  type="date"
                  value={toDate}
                  onChange={(event) => setToDate(event.target.value)}
                  min={fromDate || undefined}
                />
              </div>

              <div className="reports-filter-group">
                <label htmlFor="ip-address">IP Address</label>
                <input
                  id="ip-address"
                  type="text"
                  value={ipAddress}
                  onChange={(event) => setIpAddress(event.target.value)}
                  placeholder="192.168.1.1"
                />
              </div>
            </div>

            <div className="reports-filter-actions">
              <div className="reports-filter-actions-left">
                <button
                  type="button"
                  className="primary-btn"
                  onClick={() => fetchReports(true)}
                  disabled={refreshing}
                >
                  {refreshing ? "Applying..." : "Apply Filters"}
                </button>
                <button type="button" className="reports-filter-clear" onClick={resetFilters}>
                  Clear Filters
                </button>
              </div>

              <button
                type="button"
                className="secondary-btn"
                onClick={handleExportLogs}
                disabled={!isAdmin || exporting === "logs"}
              >
                {exporting === "logs" ? "Exporting Logs..." : "Export Logs CSV"}
              </button>
            </div>
          </div>
        </section>

        <section className="reports-summary">
          <div className="reports-summary-card reports-summary-card--blue">
            <div className="reports-summary-card__icon">| |</div>
            <strong>{reportSummary.totalRecords}</strong>
            <span>Total Records</span>
          </div>

          <div className="reports-summary-card reports-summary-card--red">
            <div className="reports-summary-card__icon">!</div>
            <strong>{reportSummary.threatsDetected}</strong>
            <span>Threats Detected</span>
          </div>

          <div className="reports-summary-card reports-summary-card--green">
            <div className="reports-summary-card__icon">OK</div>
            <strong>{reportSummary.normalTraffic}</strong>
            <span>Normal Traffic</span>
          </div>

          <div className="reports-summary-card reports-summary-card--amber">
            <div className="reports-summary-card__icon">%</div>
            <strong>{reportSummary.averageConfidence}%</strong>
            <span>Average Confidence</span>
          </div>
        </section>

        <section className="reports-charts">
          <div className="reports-chart-card">
            <div className="reports-chart-card__bar">Attack Types Distribution</div>
            <div className="reports-chart-card__body">
              <div className="reports-chart-area">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackDistribution}>
                    <CartesianGrid stroke="#e5e7eb" vertical={false} />
                    <XAxis dataKey="name" tick={{ fill: "#6b7280", fontSize: 12 }} />
                    <YAxis tick={{ fill: "#6b7280", fontSize: 12 }} allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                      {attackDistribution.map((entry, index) => (
                        <Cell key={entry.name} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="reports-chart-card">
            <div className="reports-chart-card__bar">Prediction Results</div>
            <div className="reports-chart-card__body">
              <div className="reports-chart-area">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={predictionResults}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={55}
                      outerRadius={100}
                      paddingAngle={4}
                    >
                      <Cell fill="#ef5a4f" />
                      <Cell fill="#1faa5d" />
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </section>

        <section className="reports-table-card">
          <div className="reports-table-card__bar">Detailed Detection Reports (Last 500)</div>
          <div className="reports-table-card__body">
            <div className="reports-table-controls">
              <div className="reports-table-controls-right">
                <select
                  value={rowsPerPage}
                  onChange={(event) => setRowsPerPage(event.target.value)}
                >
                  <option value="10">10 per page</option>
                  <option value="25">25 per page</option>
                  <option value="50">50 per page</option>
                </select>

                <input
                  type="text"
                  placeholder="Search..."
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                />
              </div>

              <span className="live-badge">
                {socketState.connectionStatus === "connected" ? "Live reports active" : "Live sync paused"}
              </span>
            </div>

            {detailedRows.length > 0 ? (
              <div className="reports-table-wrapper">
                <table className="reports-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Timestamp</th>
                      <th>IP Address</th>
                      <th>Prediction</th>
                      <th>Attack Type</th>
                      <th>Confidence</th>
                      <th>Source</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detailedRows.map((row) => (
                      <tr key={row.id}>
                        <td>{row.id}</td>
                        <td>{row.timestamp}</td>
                        <td className="ip-cell">{row.ipAddress}</td>
                        <td><span className="reports-table-tag">{row.prediction}</span></td>
                        <td><span className="reports-attack-pill">{row.attackType}</span></td>
                        <td><span className="reports-confidence">{row.confidence}</span></td>
                        <td><span className="reports-source-pill">{row.source}</span></td>
                        <td><span className="reports-eye">o</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state">
                <h3>No detailed report rows available</h3>
                <p>Matching detection rows will appear here after the current filters are applied.</p>
              </div>
            )}
          </div>
        </section>
      </div>
    </MainLayout>
  );
};

export default Reports;
