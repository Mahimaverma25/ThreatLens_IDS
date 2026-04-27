import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { incidents, users } from "../services/api";
import { useAuth } from "../context/AuthContext";
import useSocket from "../hooks/useSocket";
import "../styles/incidents.css";

const STATUS_OPTIONS = ["Open", "Investigating", "Resolved", "False Positive"];
const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];

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

const safeArray = (value) => (Array.isArray(value) ? value : []);

const normalize = (value) => String(value || "").trim().toLowerCase();

const severityClass = (severity) => {
  const value = normalize(severity);
  if (value === "critical") return "status-error";
  if (value === "high") return "status-warning";
  if (value === "medium") return "status-info";
  return "status-success";
};

const statusClass = (status) => {
  const value = normalize(status);
  if (value === "open") return "status-error";
  if (value === "investigating") return "status-warning";
  if (value === "resolved") return "status-success";
  return "status-info";
};

const Incidents = () => {
  const { user } = useAuth();
  const token = localStorage.getItem("accessToken");

  const [incidentRows, setIncidentRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const [filters, setFilters] = useState({
    status: "",
    severity: "",
    search: "",
  });

  const [selectedIncidentId, setSelectedIncidentId] = useState("");
  const [statusDraft, setStatusDraft] = useState("Investigating");
  const [noteDraft, setNoteDraft] = useState("");
  const [ownerDraft, setOwnerDraft] = useState("");
  const [userList, setUserList] = useState([]);
  const [liveFeed, setLiveFeed] = useState([]);

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
        console.error("Incident fetch error:", fetchError);
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
    } catch (fetchError) {
      console.error("Incident users fetch error:", fetchError);
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

  const socketHandlers = useMemo(
    () => ({
      "socket:ready": () => {
        setLiveFeed((current) =>
          [
            {
              id: `socket-${Date.now()}`,
              title: "Live incident channel connected",
              meta: "ThreatLens is listening for incident and alert updates.",
              timestamp: new Date().toISOString(),
              severity: "Low",
            },
            ...current,
          ].slice(0, 10)
        );
      },

      "incidents:new": (event) => {
        const incident = event?.data || event;

        if (incident?._id) {
          setIncidentRows((current) => {
            const exists = current.some((item) => item._id === incident._id);
            if (exists) return current;
            return [incident, ...current].slice(0, 100);
          });

          setLiveFeed((current) =>
            [
              {
                id: `incident-new-${incident._id}`,
                title: `New incident: ${incident.title || "Security Incident"}`,
                meta: `${incident.severity || "Unknown"} / ${incident.status || "Open"}`,
                timestamp: incident.createdAt || new Date().toISOString(),
                severity: incident.severity || "Medium",
              },
              ...current,
            ].slice(0, 10)
          );
        }

        fetchIncidents(true);
      },

      "incidents:update": (event) => {
        const incident = event?.data || event;

        if (incident?._id) {
          setIncidentRows((current) =>
            current.map((item) => (item._id === incident._id ? { ...item, ...incident } : item))
          );

          setLiveFeed((current) =>
            [
              {
                id: `incident-update-${incident._id}-${Date.now()}`,
                title: `Incident updated: ${incident.title || incident.incidentId}`,
                meta: `${incident.status || "Updated"} / ${incident.owner?.email || "Unassigned"}`,
                timestamp: new Date().toISOString(),
                severity: incident.severity || "Low",
              },
              ...current,
            ].slice(0, 10)
          );
        }

        fetchIncidents(true);
      },

      "alerts:new": () => fetchIncidents(true),
      "dashboard:update": () => fetchIncidents(true),
    }),
    [fetchIncidents]
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
        normalize(incident.sourceIps?.join(" ")).includes(search) ||
        normalize(incident.severity).includes(search) ||
        normalize(incident.status).includes(search);

      return matchesSearch;
    });
  }, [incidentRows, filters.search]);

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
      setRefreshing(true);

      await incidents.update(selectedIncidentId, {
        status: statusDraft,
        note: noteDraft.trim() || undefined,
        owner: ownerDraft || undefined,
      });

      setNoteDraft("");
      await fetchIncidents(true);
    } catch (updateError) {
      console.error("Incident update error:", updateError);
      setError(updateError?.response?.data?.message || "Failed to update incident");
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
      <div className="incident-page">
        <section className="command-header">
          <div>
            <div className="command-eyebrow">
              ThreatLens / Incident Management / Live SOC Workflow
            </div>
            <h1>Incident Center</h1>
            <p>
              Investigate correlated IDS alerts, assign owners, update case status, and monitor
              live incident activity from your ThreatLens pipeline.
            </p>

            <div className="command-meta">
              <span className={`status-pill ${socketState.connectionStatus === "connected" ? "status-success" : "status-warning"}`}>
                Socket: {socketState.connectionStatus}
              </span>
              <span>Last updated: {lastUpdated ? formatDateTime(lastUpdated) : "Never"}</span>
            </div>
          </div>

          <div className="command-actions">
            <button className="btn-outline" onClick={() => fetchIncidents()} disabled={refreshing}>
              {refreshing ? "Refreshing..." : "Refresh Incidents"}
            </button>
            <button className="btn-primary" onClick={exportIncidentsCsv}>
              Export CSV
            </button>
          </div>
        </section>

        {error ? <div className="error-message">{error}</div> : null}

        <section className="hero-metric-grid incident-overview-grid">
          <div className="hero-metric-card">
            <span>Total Incidents</span>
            <strong>{overview.total}</strong>
            <small>All correlated cases</small>
          </div>

          <div className="hero-metric-card">
            <span>Open</span>
            <strong>{overview.open}</strong>
            <small>Awaiting triage</small>
          </div>

          <div className="hero-metric-card">
            <span>Investigating</span>
            <strong>{overview.investigating}</strong>
            <small>Active analyst workflow</small>
          </div>

          <div className="hero-metric-card">
            <span>Critical</span>
            <strong>{overview.critical}</strong>
            <small>Immediate response required</small>
          </div>

          <div className="hero-metric-card">
            <span>Linked Alerts</span>
            <strong>{overview.linkedAlerts}</strong>
            <small>Signals grouped into incidents</small>
          </div>
        </section>

        <div className="controls glass incident-filters">
          <input
            className="search-input"
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
        </div>

        <div className="dashboard-grid dashboard-grid--premium">
          <div className="dashboard-panel panel-span-2 glass animate-in">
            <div className="panel-header">
              <div>
                <h3>Active Incident Queue</h3>
                <span>{filteredRows.length} incidents matching current view</span>
              </div>
            </div>

            <div className="panel-table">
              <table>
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
                        className={`incident-row${
                          selectedIncidentId === incident._id ? " incident-row--active" : ""
                        }`}
                        onClick={() => handleSelectIncident(incident)}
                      >
                        <td>
                          <div className="incident-row__title">
                            {incident.title || "Security Incident"}
                          </div>
                          <small className="incident-row__meta">
                            {incident.incidentId || incident._id}
                          </small>
                        </td>

                        <td className="mono">
                          {safeArray(incident.sourceIps)[0] || "-"}
                        </td>

                        <td>
                          <span
                            className={`status-dot ${severityClass(
                              incident.severity
                            )} incident-severity-dot`}
                          />
                          {incident.severity || "Unknown"}
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
                        <div className="incident-empty-state">
                          No incidents found for the selected filters.
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="dashboard-panel glass animate-in">
            <div className="panel-header">
              <div>
                <h3>Case Details</h3>
                <span>Workflow manager</span>
              </div>
            </div>

            {selectedIncident ? (
              <div className="panel-list">
                <div className="list-row list-row--pill">
                  <span>ID</span>
                  <strong>{selectedIncident.incidentId || selectedIncident._id}</strong>
                </div>

                <div className="list-row list-row--pill">
                  <span>Severity</span>
                  <strong>{selectedIncident.severity || "Unknown"}</strong>
                </div>

                <div className="list-row list-row--pill">
                  <span>Status</span>
                  <strong>{selectedIncident.status || "Open"}</strong>
                </div>

                <div className="list-row list-row--pill">
                  <span>Owner</span>
                  <strong>{selectedIncident.owner?.email || "Unassigned"}</strong>
                </div>

                <div className="list-row list-row--pill">
                  <span>Source IPs</span>
                  <strong>{safeArray(selectedIncident.sourceIps).join(", ") || "-"}</strong>
                </div>

                <div className="incident-case-form">
                  <label className="panel-label">Update Status</label>
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

                  {user?.role === "admin" ? (
                    <>
                      <label className="panel-label">Assign Owner</label>
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
                  ) : null}

                  <label className="panel-label">Add Investigation Note</label>
                  <textarea
                    value={noteDraft}
                    onChange={(event) => setNoteDraft(event.target.value)}
                    placeholder="Write investigation findings, action taken, or next step..."
                    className="incident-note-input"
                    disabled={!isAnalyst}
                  />

                  <button
                    className="btn-primary"
                    onClick={handleUpdateIncident}
                    disabled={!isAnalyst || refreshing}
                  >
                    {refreshing ? "Updating..." : "Update Case"}
                  </button>

                  {!isAnalyst ? (
                    <div className="incident-note-hint">
                      Viewer role can monitor incidents only. Updates are available to analyst and admin.
                    </div>
                  ) : null}
                </div>

                <div className="incident-timeline">
                  <h4 className="panel-label incident-timeline__title">Case Timeline</h4>

                  <div className="incident-timeline__rail">
                    {safeArray(selectedIncident.notes).length ? (
                      safeArray(selectedIncident.notes).map((entry, index) => (
                        <div key={`${entry.timestamp}-${index}`} className="incident-timeline__entry">
                          <span className="incident-timeline__dot" />

                          <div className="incident-timeline__meta">
                            {entry.by?.email || "System"} • {formatTime(entry.timestamp)}
                          </div>

                          <div className="incident-timeline__note">{entry.note}</div>
                        </div>
                      ))
                    ) : (
                      <div className="incident-empty-note">No notes recorded yet.</div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="incident-empty-state">Select an incident to view details.</div>
            )}
          </div>
        </div>

        <div className="dashboard-grid dashboard-grid--premium">
          <div className="dashboard-panel glass animate-in">
            <div className="panel-header">
              <div>
                <h3>Live Incident Activity</h3>
                <span>Socket and pipeline updates</span>
              </div>
            </div>

            <div className="incident-live-feed">
              {liveFeed.length ? (
                liveFeed.map((item) => (
                  <div key={item.id} className="incident-live-feed__item">
                    <div>
                      <strong>{item.title}</strong>
                      <span>{item.meta}</span>
                    </div>
                    <small>{formatTime(item.timestamp)}</small>
                  </div>
                ))
              ) : (
                <div className="incident-empty-state">
                  Waiting for live incident updates from backend.
                </div>
              )}
            </div>
          </div>

          <div className="dashboard-panel glass animate-in">
            <div className="panel-header">
              <div>
                <h3>Incident Summary</h3>
                <span>Current SOC posture</span>
              </div>
            </div>

            <div className="panel-list">
              <div className="list-row list-row--pill">
                <span>High/Critical Cases</span>
                <strong>{overview.critical + overview.high}</strong>
              </div>

              <div className="list-row list-row--pill">
                <span>Resolved Cases</span>
                <strong>{overview.resolved}</strong>
              </div>

              <div className="list-row list-row--pill">
                <span>Socket Status</span>
                <strong>{socketState.connectionStatus}</strong>
              </div>

              <div className="list-row list-row--pill">
                <span>Role Access</span>
                <strong>{user?.role || "viewer"}</strong>
              </div>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default Incidents;
