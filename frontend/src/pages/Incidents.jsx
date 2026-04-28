import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { incidents, users } from "../services/api";
import { useAuth } from "../context/AuthContext";
import useSocket from "../hooks/useSocket";

const STATUS_OPTIONS = ["Open", "Investigating", "Resolved", "False Positive"];
const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];

const safeArray = (value) => (Array.isArray(value) ? value : []);
const normalize = (value) => String(value || "").trim().toLowerCase();

const formatDateTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const formatTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleTimeString();
};

const severityClass = (severity) => {
  const value = normalize(severity);
  if (value === "critical") return "severity-critical";
  if (value === "high") return "severity-high";
  if (value === "medium") return "severity-medium";
  return "severity-low";
};

const statusClass = (status) => {
  const value = normalize(status);
  if (value === "open") return "status-open";
  if (value === "investigating") return "status-investigating";
  if (value === "resolved") return "status-resolved";
  return "status-false";
};

const Incidents = () => {
  const { user } = useAuth();
  const token = localStorage.getItem("accessToken");

  const [incidentRows, setIncidentRows] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState("");
  const [userList, setUserList] = useState([]);
  const [liveFeed, setLiveFeed] = useState([]);

  const [filters, setFilters] = useState({
    status: "",
    severity: "",
    search: "",
  });

  const [statusDraft, setStatusDraft] = useState("Investigating");
  const [noteDraft, setNoteDraft] = useState("");
  const [ownerDraft, setOwnerDraft] = useState("");

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const isMountedRef = useRef(true);
  const pollingRef = useRef(null);

  const isAnalyst = ["admin", "analyst"].includes(user?.role);

  const buildActiveFilters = useCallback(() => {
    return Object.fromEntries(
      Object.entries(filters).filter(([, value]) => String(value || "").trim() !== "")
    );
  }, [filters]);

  const fetchIncidents = useCallback(
    async (silent = false) => {
      try {
        if (!silent) setLoading(true);
        setRefreshing(true);
        setError("");

        const response = await incidents.list(buildActiveFilters());
        const rows = safeArray(response?.data?.data);

        if (!isMountedRef.current) return;

        setIncidentRows(rows);
        setLastUpdated(new Date());

        setSelectedIncidentId((current) => {
          if (current && rows.some((item) => item._id === current)) return current;
          return rows[0]?._id || "";
        });
      } catch (fetchError) {
        if (isMountedRef.current) {
          setError(
            fetchError?.response?.data?.message ||
              "Failed to load incidents. Please check backend incident routes."
          );
        }
      } finally {
        if (isMountedRef.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [buildActiveFilters]
  );

  const fetchUsers = useCallback(async () => {
    if (user?.role !== "admin") return;

    try {
      const response = await users.list();
      setUserList(safeArray(response?.data?.data));
    } catch {
      // Keep incident page usable even if user list is unavailable.
    }
  }, [user?.role]);

  useEffect(() => {
    isMountedRef.current = true;
    fetchIncidents();
    fetchUsers();

    pollingRef.current = setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchIncidents(true);
      }
    }, 30000);

    return () => {
      isMountedRef.current = false;
      clearInterval(pollingRef.current);
    };
  }, [fetchIncidents, fetchUsers]);

  const selectedIncident = useMemo(
    () => incidentRows.find((incident) => incident._id === selectedIncidentId) || null,
    [incidentRows, selectedIncidentId]
  );

  useEffect(() => {
    if (!selectedIncident) return;
    setStatusDraft(selectedIncident.status || "Investigating");
    setOwnerDraft(selectedIncident.owner?._id || "");
  }, [selectedIncident]);

  const addLiveFeed = useCallback((item) => {
    setLiveFeed((current) =>
      [
        {
          id: `${item.title}-${Date.now()}-${Math.random()}`,
          timestamp: new Date().toISOString(),
          severity: "Low",
          ...item,
        },
        ...current,
      ].slice(0, 10)
    );
  }, []);

  const socketHandlers = useMemo(
    () => ({
      "socket:ready": () => {
        addLiveFeed({
          title: "Live incident channel connected",
          meta: "ThreatLens is listening for incident and alert updates.",
          severity: "Low",
        });
      },

      "incidents:new": (event) => {
        const incident = event?.data || event;

        if (incident?._id) {
          setIncidentRows((current) => {
            const exists = current.some((item) => item._id === incident._id);
            if (exists) return current;
            return [incident, ...current].slice(0, 100);
          });

          addLiveFeed({
            title: `New incident: ${incident.title || "Security Incident"}`,
            meta: `${incident.severity || "Unknown"} / ${incident.status || "Open"}`,
            timestamp: incident.createdAt || new Date().toISOString(),
            severity: incident.severity || "Medium",
          });
        }

        fetchIncidents(true);
      },

      "incidents:update": (event) => {
        const incident = event?.data || event;

        if (incident?._id) {
          setIncidentRows((current) =>
            current.map((item) =>
              item._id === incident._id ? { ...item, ...incident } : item
            )
          );

          addLiveFeed({
            title: `Incident updated: ${incident.title || incident.incidentId}`,
            meta: `${incident.status || "Updated"} / ${
              incident.owner?.email || "Unassigned"
            }`,
            severity: incident.severity || "Low",
          });
        }

        fetchIncidents(true);
      },

      "alerts:new": () => fetchIncidents(true),
      "dashboard:update": () => fetchIncidents(true),
    }),
    [addLiveFeed, fetchIncidents]
  );

  const socketState = useSocket(token, socketHandlers);

  const overview = useMemo(
    () =>
      incidentRows.reduce(
        (acc, incident) => {
          const status = normalize(incident.status);
          const severity = normalize(incident.severity);

          acc.total += 1;
          if (status === "open") acc.open += 1;
          if (status === "investigating") acc.investigating += 1;
          if (status === "resolved") acc.resolved += 1;
          if (severity === "critical") acc.critical += 1;
          if (severity === "high") acc.high += 1;
          acc.linkedAlerts += Number(incident.alertIds?.length || 0);

          return acc;
        },
        {
          total: 0,
          open: 0,
          investigating: 0,
          resolved: 0,
          critical: 0,
          high: 0,
          linkedAlerts: 0,
        }
      ),
    [incidentRows]
  );

  const filteredRows = useMemo(() => {
    const search = normalize(filters.search);

    return incidentRows.filter((incident) => {
      const matchesSearch =
        !search ||
        normalize(incident.title).includes(search) ||
        normalize(incident.incidentId).includes(search) ||
        normalize(safeArray(incident.sourceIps).join(" ")).includes(search) ||
        normalize(incident.severity).includes(search) ||
        normalize(incident.status).includes(search);

      const matchesStatus = !filters.status || incident.status === filters.status;
      const matchesSeverity = !filters.severity || incident.severity === filters.severity;

      return matchesSearch && matchesStatus && matchesSeverity;
    });
  }, [incidentRows, filters]);

  const handleSelectIncident = (incident) => {
    setSelectedIncidentId(incident._id);
    setStatusDraft(incident.status || "Investigating");
    setOwnerDraft(incident.owner?._id || "");
    setNoteDraft("");
  };

  const handleUpdateIncident = async () => {
    if (!selectedIncidentId || !isAnalyst) return;

    try {
      setError("");
      setFeedback("");
      setRefreshing(true);

      await incidents.update(selectedIncidentId, {
        status: statusDraft,
        note: noteDraft.trim() || undefined,
        owner: ownerDraft || undefined,
      });

      setNoteDraft("");
      setFeedback("Incident updated successfully.");
      await fetchIncidents(true);
    } catch (updateError) {
      setError(updateError?.response?.data?.message || "Failed to update incident.");
    } finally {
      setRefreshing(false);
    }
  };

  const exportIncidentsCsv = () => {
    if (!filteredRows.length) return;

    const rows = filteredRows.map((incident) => ({
      incidentId: incident.incidentId || "",
      title: incident.title || "",
      severity: incident.severity || "",
      status: incident.status || "",
      sourceIps: safeArray(incident.sourceIps).join(" | "),
      alerts: incident.alertIds?.length || 0,
      owner: incident.owner?.email || "Unassigned",
      firstSeen: formatDateTime(incident.firstSeen || incident.createdAt),
      lastSeen: formatDateTime(incident.lastSeen || incident.updatedAt),
    }));

    const headers = Object.keys(rows[0]);
    const csv = [
      headers.join(","),
      ...rows.map((row) =>
        headers.map((header) => `"${String(row[header] ?? "").replace(/"/g, '""')}"`).join(",")
      ),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = `threatlens-incidents-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();

    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Building live incident center...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <style>{`
        .incident-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background: linear-gradient(135deg, #fff7ed 0%, #f8fbff 55%, #eef9f1 100%);
        }

        .incident-shell {
          max-width: 1280px;
          margin: 0 auto;
        }

        .incident-header {
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

        .incident-eyebrow {
          color: #0ea5e9;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: .12em;
          margin-bottom: 8px;
        }

        .incident-header h1 {
          margin: 0;
          font-size: 34px;
          color: #0f2742;
        }

        .incident-header p {
          margin: 10px 0 0;
          color: #64748b;
          line-height: 1.6;
          max-width: 760px;
        }

        .incident-meta {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          margin-top: 16px;
          color: #64748b;
          font-size: 13px;
        }

        .incident-actions {
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
          color: #fff;
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
          box-shadow: 0 12px 26px rgba(37,99,235,.22);
        }

        .secondary-btn {
          background: #eef6ff;
          color: #0f2742;
          border: 1px solid #dbeafe;
        }

        .primary-btn:disabled,
        .secondary-btn:disabled {
          opacity: .6;
          cursor: not-allowed;
        }

        .incident-metrics {
          display: grid;
          grid-template-columns: repeat(5, minmax(0, 1fr));
          gap: 18px;
          margin-bottom: 22px;
        }

        .incident-metric-card,
        .incident-panel {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          box-shadow: 0 14px 34px rgba(15,23,42,.07);
        }

        .incident-metric-card {
          border-radius: 20px;
          padding: 22px;
        }

        .incident-metric-card span {
          display: block;
          font-size: 12px;
          color: #64748b;
          font-weight: 900;
          text-transform: uppercase;
          margin-bottom: 10px;
        }

        .incident-metric-card strong {
          font-size: 30px;
          color: #0f2742;
        }

        .incident-metric-card small {
          display: block;
          color: #64748b;
          margin-top: 7px;
        }

        .incident-filters {
          display: grid;
          grid-template-columns: 2fr 1fr 1fr;
          gap: 14px;
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 20px;
          padding: 18px;
          margin-bottom: 22px;
          box-shadow: 0 14px 34px rgba(15,23,42,.06);
        }

        .incident-filters input,
        .incident-filters select,
        .case-form select,
        .case-form textarea {
          width: 100%;
          border: 1px solid #dbe3ef;
          background: #f8fbff;
          border-radius: 14px;
          padding: 13px 14px;
          outline: none;
          color: #172033;
          font-size: 14px;
        }

        .incident-filters input:focus,
        .incident-filters select:focus,
        .case-form select:focus,
        .case-form textarea:focus {
          border-color: #0ea5e9;
          box-shadow: 0 0 0 4px rgba(14,165,233,.12);
          background: #fff;
        }

        .incident-grid {
          display: grid;
          grid-template-columns: minmax(0, 2fr) minmax(360px, .9fr);
          gap: 22px;
          align-items: start;
          margin-bottom: 22px;
        }

        .incident-panel {
          border-radius: 24px;
          overflow: hidden;
        }

        .incident-panel-header {
          padding: 22px 24px;
          border-bottom: 1px solid #eef2f7;
        }

        .incident-panel-header h3 {
          margin: 0;
          color: #172033;
          font-size: 21px;
        }

        .incident-panel-header span {
          display: block;
          margin-top: 6px;
          color: #64748b;
          font-size: 13px;
        }

        .incident-table-wrapper {
          overflow-x: auto;
        }

        .incident-table {
          width: 100%;
          border-collapse: collapse;
          min-width: 900px;
        }

        .incident-table th,
        .incident-table td {
          text-align: left;
          padding: 16px 18px;
          border-bottom: 1px solid #eef2f7;
          vertical-align: top;
        }

        .incident-table th {
          background: #f8fbff;
          color: #475569;
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: .08em;
        }

        .incident-row {
          cursor: pointer;
          transition: .2s ease;
        }

        .incident-row:hover,
        .incident-row.active {
          background: #eff6ff;
        }

        .incident-title {
          color: #0f2742;
          font-weight: 900;
          margin-bottom: 5px;
        }

        .incident-subtext {
          color: #64748b;
          font-size: 12px;
        }

        .mono {
          font-family: Consolas, monospace;
          font-weight: 800;
        }

        .status-pill,
        .severity-pill {
          display: inline-flex;
          padding: 6px 10px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 900;
          white-space: nowrap;
        }

        .severity-critical,
        .status-open {
          background: #fee2e2;
          color: #991b1b;
        }

        .severity-high,
        .status-investigating {
          background: #ffedd5;
          color: #9a3412;
        }

        .severity-medium {
          background: #fef9c3;
          color: #854d0e;
        }

        .severity-low,
        .status-resolved {
          background: #dcfce7;
          color: #166534;
        }

        .status-false {
          background: #f1f5f9;
          color: #64748b;
        }

        .case-details {
          padding: 20px 24px 24px;
          display: grid;
          gap: 12px;
        }

        .case-row {
          background: #f8fbff;
          border: 1px solid #e2e8f0;
          border-radius: 16px;
          padding: 14px 16px;
          display: grid;
          gap: 6px;
        }

        .case-row span,
        .case-form label {
          color: #64748b;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }

        .case-row strong {
          color: #0f2742;
          overflow-wrap: anywhere;
        }

        .case-form {
          display: grid;
          gap: 12px;
          margin-top: 8px;
        }

        .case-form textarea {
          min-height: 110px;
          resize: vertical;
        }

        .timeline {
          margin-top: 10px;
          border-top: 1px solid #eef2f7;
          padding-top: 16px;
        }

        .timeline h4 {
          margin: 0 0 12px;
          color: #172033;
        }

        .timeline-entry {
          position: relative;
          padding-left: 22px;
          margin-bottom: 16px;
        }

        .timeline-entry::before {
          content: "";
          position: absolute;
          left: 0;
          top: 5px;
          width: 10px;
          height: 10px;
          border-radius: 99px;
          background: #0ea5e9;
        }

        .timeline-meta {
          color: #64748b;
          font-size: 12px;
          font-weight: 800;
          margin-bottom: 4px;
        }

        .timeline-note {
          color: #172033;
          line-height: 1.5;
        }

        .lower-grid {
          display: grid;
          grid-template-columns: 1.1fr .9fr;
          gap: 22px;
        }

        .live-feed {
          padding: 20px 24px 24px;
          display: grid;
          gap: 12px;
        }

        .live-feed-item {
          display: flex;
          justify-content: space-between;
          gap: 14px;
          background: #f8fbff;
          border: 1px solid #e2e8f0;
          border-radius: 16px;
          padding: 14px 16px;
        }

        .live-feed-item strong {
          display: block;
          color: #172033;
          margin-bottom: 4px;
        }

        .live-feed-item span,
        .live-feed-item small {
          color: #64748b;
          font-size: 12px;
        }

        .summary-list {
          padding: 20px 24px 24px;
          display: grid;
          gap: 12px;
        }

        .empty-state {
          padding: 38px 20px;
          text-align: center;
          color: #64748b;
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

        .success-message {
          background: #ecfdf5;
          color: #047857;
          border: 1px solid #bbf7d0;
          border-radius: 14px;
          padding: 14px 16px;
          margin-bottom: 18px;
          font-weight: 800;
        }

        @media (max-width: 1100px) {
          .incident-metrics {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .incident-grid,
          .lower-grid {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 720px) {
          .incident-page {
            padding: 16px;
          }

          .incident-header {
            flex-direction: column;
            padding: 24px;
          }

          .incident-header h1 {
            font-size: 28px;
          }

          .incident-actions,
          .primary-btn,
          .secondary-btn {
            width: 100%;
          }

          .incident-filters {
            grid-template-columns: 1fr;
          }

          .incident-metrics {
            grid-template-columns: 1fr;
          }
        }
      `}</style>

      <div className="incident-page">
        <div className="incident-shell">
          <section className="incident-header">
            <div>
              <div className="incident-eyebrow">
                ThreatLens / Incident Management / Live SOC Workflow
              </div>
              <h1>Incident Center</h1>
              <p>
                Investigate correlated IDS alerts, assign owners, update case status,
                add investigation notes, and monitor live incident activity.
              </p>

              <div className="incident-meta">
                <span
                  className={`status-pill ${
                    socketState.connectionStatus === "connected"
                      ? "status-resolved"
                      : "status-investigating"
                  }`}
                >
                  Socket: {socketState.connectionStatus}
                </span>
                <span>
                  Last updated: {lastUpdated ? formatDateTime(lastUpdated) : "Never"}
                </span>
              </div>
            </div>

            <div className="incident-actions">
              <button
                type="button"
                className="secondary-btn"
                onClick={() => fetchIncidents()}
                disabled={refreshing}
              >
                {refreshing ? "Refreshing..." : "Refresh Incidents"}
              </button>

              <button
                type="button"
                className="primary-btn"
                onClick={exportIncidentsCsv}
                disabled={!filteredRows.length}
              >
                Export CSV
              </button>
            </div>
          </section>

          {error && <div className="error-message">{error}</div>}
          {feedback && <div className="success-message">{feedback}</div>}

          <section className="incident-metrics">
            <div className="incident-metric-card">
              <span>Total Incidents</span>
              <strong>{overview.total}</strong>
              <small>All correlated cases</small>
            </div>

            <div className="incident-metric-card">
              <span>Open</span>
              <strong>{overview.open}</strong>
              <small>Awaiting triage</small>
            </div>

            <div className="incident-metric-card">
              <span>Investigating</span>
              <strong>{overview.investigating}</strong>
              <small>Active analyst workflow</small>
            </div>

            <div className="incident-metric-card">
              <span>Critical</span>
              <strong>{overview.critical}</strong>
              <small>Immediate response required</small>
            </div>

            <div className="incident-metric-card">
              <span>Linked Alerts</span>
              <strong>{overview.linkedAlerts}</strong>
              <small>Signals grouped into incidents</small>
            </div>
          </section>

          <section className="incident-filters">
            <input
              placeholder="Search by incident name, ID, IP, status, or severity..."
              value={filters.search}
              onChange={(event) =>
                setFilters((current) => ({ ...current, search: event.target.value }))
              }
            />

            <select
              value={filters.status}
              onChange={(event) =>
                setFilters((current) => ({ ...current, status: event.target.value }))
              }
            >
              <option value="">All Statuses</option>
              {STATUS_OPTIONS.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>

            <select
              value={filters.severity}
              onChange={(event) =>
                setFilters((current) => ({ ...current, severity: event.target.value }))
              }
            >
              <option value="">All Severities</option>
              {SEVERITY_OPTIONS.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </section>

          <section className="incident-grid">
            <div className="incident-panel">
              <div className="incident-panel-header">
                <h3>Active Incident Queue</h3>
                <span>{filteredRows.length} incidents matching current view</span>
              </div>

              <div className="incident-table-wrapper">
                <table className="incident-table">
                  <thead>
                    <tr>
                      <th>Incident</th>
                      <th>Source IP</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Alerts</th>
                      <th>Owner</th>
                      <th>Last Seen</th>
                    </tr>
                  </thead>

                  <tbody>
                    {filteredRows.length ? (
                      filteredRows.map((incident) => (
                        <tr
                          key={incident._id}
                          className={`incident-row ${
                            selectedIncidentId === incident._id ? "active" : ""
                          }`}
                          onClick={() => handleSelectIncident(incident)}
                        >
                          <td>
                            <div className="incident-title">
                              {incident.title || "Security Incident"}
                            </div>
                            <div className="incident-subtext">
                              {incident.incidentId || incident._id}
                            </div>
                          </td>

                          <td className="mono">
                            {safeArray(incident.sourceIps)[0] || "-"}
                          </td>

                          <td>
                            <span
                              className={`severity-pill ${severityClass(
                                incident.severity
                              )}`}
                            >
                              {incident.severity || "Unknown"}
                            </span>
                          </td>

                          <td>
                            <span className={`status-pill ${statusClass(incident.status)}`}>
                              {incident.status || "Open"}
                            </span>
                          </td>

                          <td>{incident.alertIds?.length || 0}</td>
                          <td>{incident.owner?.email || "Unassigned"}</td>
                          <td>{formatDateTime(incident.lastSeen || incident.updatedAt)}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="7">
                          <div className="empty-state">
                            No incidents found for the selected filters.
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <aside className="incident-panel">
              <div className="incident-panel-header">
                <h3>Case Details</h3>
                <span>Workflow manager</span>
              </div>

              {selectedIncident ? (
                <div className="case-details">
                  <div className="case-row">
                    <span>ID</span>
                    <strong>{selectedIncident.incidentId || selectedIncident._id}</strong>
                  </div>

                  <div className="case-row">
                    <span>Severity</span>
                    <strong>{selectedIncident.severity || "Unknown"}</strong>
                  </div>

                  <div className="case-row">
                    <span>Status</span>
                    <strong>{selectedIncident.status || "Open"}</strong>
                  </div>

                  <div className="case-row">
                    <span>Owner</span>
                    <strong>{selectedIncident.owner?.email || "Unassigned"}</strong>
                  </div>

                  <div className="case-row">
                    <span>Source IPs</span>
                    <strong>{safeArray(selectedIncident.sourceIps).join(", ") || "-"}</strong>
                  </div>

                  <div className="case-form">
                    <label>Update Status</label>
                    <select
                      value={statusDraft}
                      onChange={(event) => setStatusDraft(event.target.value)}
                      disabled={!isAnalyst}
                    >
                      {STATUS_OPTIONS.map((status) => (
                        <option key={status} value={status}>
                          {status}
                        </option>
                      ))}
                    </select>

                    {user?.role === "admin" && (
                      <>
                        <label>Assign Owner</label>
                        <select
                          value={ownerDraft}
                          onChange={(event) => setOwnerDraft(event.target.value)}
                        >
                          <option value="">Unassigned</option>
                          {userList.map((member) => (
                            <option key={member._id} value={member._id}>
                              {member.email || member.username || member._id}
                            </option>
                          ))}
                        </select>
                      </>
                    )}

                    <label>Add Investigation Note</label>
                    <textarea
                      value={noteDraft}
                      onChange={(event) => setNoteDraft(event.target.value)}
                      placeholder="Write investigation findings, action taken, or next step..."
                      disabled={!isAnalyst}
                    />

                    <button
                      type="button"
                      className="primary-btn"
                      onClick={handleUpdateIncident}
                      disabled={!isAnalyst || refreshing}
                    >
                      {refreshing ? "Updating..." : "Update Case"}
                    </button>

                    {!isAnalyst && (
                      <div className="empty-state">
                        Viewer role can monitor incidents only. Updates are available to analyst and admin.
                      </div>
                    )}
                  </div>

                  <div className="timeline">
                    <h4>Case Timeline</h4>

                    {safeArray(selectedIncident.notes).length ? (
                      safeArray(selectedIncident.notes).map((entry, index) => (
                        <div key={`${entry.timestamp}-${index}`} className="timeline-entry">
                          <div className="timeline-meta">
                            {entry.by?.email || "System"} • {formatTime(entry.timestamp)}
                          </div>
                          <div className="timeline-note">{entry.note}</div>
                        </div>
                      ))
                    ) : (
                      <div className="empty-state">No notes recorded yet.</div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="empty-state">Select an incident to view details.</div>
              )}
            </aside>
          </section>

          <section className="lower-grid">
            <div className="incident-panel">
              <div className="incident-panel-header">
                <h3>Live Incident Activity</h3>
                <span>Socket and pipeline updates</span>
              </div>

              <div className="live-feed">
                {liveFeed.length ? (
                  liveFeed.map((item) => (
                    <div key={item.id} className="live-feed-item">
                      <div>
                        <strong>{item.title}</strong>
                        <span>{item.meta}</span>
                      </div>
                      <small>{formatTime(item.timestamp)}</small>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    Waiting for live incident updates from backend.
                  </div>
                )}
              </div>
            </div>

            <div className="incident-panel">
              <div className="incident-panel-header">
                <h3>Incident Summary</h3>
                <span>Current SOC posture</span>
              </div>

              <div className="summary-list">
                <div className="case-row">
                  <span>High/Critical Cases</span>
                  <strong>{overview.critical + overview.high}</strong>
                </div>

                <div className="case-row">
                  <span>Resolved Cases</span>
                  <strong>{overview.resolved}</strong>
                </div>

                <div className="case-row">
                  <span>Socket Status</span>
                  <strong>{socketState.connectionStatus}</strong>
                </div>

                <div className="case-row">
                  <span>Role Access</span>
                  <strong>{user?.role || "viewer"}</strong>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </MainLayout>
  );
};

export default Incidents;