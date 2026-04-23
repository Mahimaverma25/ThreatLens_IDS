import { useCallback, useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { incidents, users } from "../services/api";
import { useAuth } from "../context/AuthContext";

const Incidents = () => {
  const { user } = useAuth();
  const [incidentRows, setIncidentRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({ status: "", severity: "", search: "" });
  const [selectedIncidentId, setSelectedIncidentId] = useState("");
  const [statusDraft, setStatusDraft] = useState("Investigating");
  const [noteDraft, setNoteDraft] = useState("");
  const [ownerDraft, setOwnerDraft] = useState("");
  const [userList, setUserList] = useState([]);
  const isAnalyst = ["admin", "analyst"].includes(user?.role);

  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      const activeFilters = Object.fromEntries(
        Object.entries(filters).filter(([, value]) => String(value || "").trim() !== "")
      );
      const response = await incidents.list(activeFilters);
      const rows = response?.data?.data ?? [];
      setIncidentRows(rows);
      setSelectedIncidentId((current) => current || rows[0]?._id || "");
    } catch (fetchError) {
      console.error("Incident fetch error:", fetchError);
      setError("Failed to load incidents");
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  useEffect(() => {
    const fetchUsers = async () => {
      if (user?.role !== "admin") return;
      try {
        const response = await users.list();
        setUserList(response?.data?.data ?? []);
      } catch (fetchError) {
        console.error("Incident users fetch error:", fetchError);
      }
    };
    fetchUsers();
  }, [user?.role]);

  useEffect(() => {
    if (!selectedIncidentId) return;

    const activeIncident =
      incidentRows.find((incident) => incident._id === selectedIncidentId) || null;

    if (!activeIncident) return;

    setStatusDraft(activeIncident.status || "Investigating");
    setOwnerDraft(activeIncident.owner?._id || "");
  }, [incidentRows, selectedIncidentId]);

  const selectedIncident = useMemo(
    () => incidentRows.find((i) => i._id === selectedIncidentId) || null,
    [incidentRows, selectedIncidentId]
  );

  const overview = useMemo(
    () =>
      incidentRows.reduce(
        (acc, i) => {
          acc.total += 1;
          if (i.status === "Investigating") acc.investigating += 1;
          if (i.status === "Open") acc.open += 1;
          if (i.severity === "Critical") acc.critical += 1;
          acc.linkedAlerts += Number(i.alertIds?.length || 0);
          return acc;
        },
        { total: 0, investigating: 0, open: 0, critical: 0, linkedAlerts: 0 }
      ),
    [incidentRows]
  );

  const handleUpdateIncident = async () => {
    if (!selectedIncidentId) return;
    try {
      setError("");
      await incidents.update(selectedIncidentId, {
        status: statusDraft,
        note: noteDraft.trim() || undefined,
        owner: ownerDraft || undefined,
      });
      setNoteDraft("");
      await fetchIncidents();
    } catch (updateError) {
      console.error("Incident update error:", updateError);
      setError("Failed to update incident");
    }
  };

  if (loading) return <MainLayout><div className="loading">Building incident timeline...</div></MainLayout>;

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Incident Management / SOC Workflow</div>
          <h1>Incident Center</h1>
          <p>Review and investigate correlated security incidents across your infrastructure.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="hero-metric-grid" style={{ marginBottom: '24px' }}>
        <div className="hero-metric-card"><span>Total Incidents</span><strong>{overview.total}</strong><small>Historical volume</small></div>
        <div className="hero-metric-card"><span>Open / New</span><strong>{overview.open}</strong><small>Awaiting triage</small></div>
        <div className="hero-metric-card"><span>Investigating</span><strong>{overview.investigating}</strong><small>In progress</small></div>
        <div className="hero-metric-card"><span>Critical Threats</span><strong>{overview.critical}</strong><small>Immediate action required</small></div>
        <div className="hero-metric-card"><span>Linked Alerts</span><strong>{overview.linkedAlerts}</strong><small>Correlated signals</small></div>
      </section>

      <div className="controls glass" style={{ marginBottom: '24px', padding: '16px' }}>
        <input className="search-input" placeholder="Search by title, IP, or type..." value={filters.search} onChange={e => setFilters(c => ({...c, search: e.target.value}))}/>
        <select value={filters.status} onChange={e => setFilters(c => ({...c, status: e.target.value}))}>
          <option value="">All Statuses</option>
          <option value="Open">Open</option>
          <option value="Investigating">Investigating</option>
          <option value="Resolved">Resolved</option>
        </select>
        <select value={filters.severity} onChange={e => setFilters(c => ({...c, severity: e.target.value}))}>
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
        </select>
        <button className="btn-outline" onClick={fetchIncidents}>Refresh</button>
      </div>

      <div className="dashboard-grid dashboard-grid--premium">
        <div className="dashboard-panel panel-span-2 glass animate-in">
          <div className="panel-header"><h3>Active Incident Queue</h3><span>Latest detections</span></div>
          <div className="panel-table">
            <table>
              <thead>
                <tr>
                  <th>Incident Name</th>
                  <th>IP Address</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Alerts</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {incidentRows.map((incident) => (
                  <tr key={incident._id} 
                      onClick={() => { setSelectedIncidentId(incident._id); setStatusDraft(incident.status || "Investigating"); setOwnerDraft(incident.owner?._id || ""); }}
                      style={{ cursor: 'pointer', background: selectedIncidentId === incident._id ? 'rgba(0, 242, 255, 0.05)' : '' }}>
                    <td><div style={{ fontWeight: '600' }}>{incident.title}</div><small style={{ color: 'var(--text-dark)' }}>{incident.incidentId}</small></td>
                    <td className="mono">{incident.sourceIps?.[0] || "-"}</td>
                    <td><span className={`status-dot ${incident.severity === 'Critical' ? 'status-error' : 'status-warning'}`} style={{ marginRight: '8px' }}></span>{incident.severity}</td>
                    <td>{incident.status}</td>
                    <td>{incident.alertIds?.length || 0}</td>
                    <td>{new Date(incident.lastSeen).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="dashboard-panel glass animate-in">
          <div className="panel-header"><h3>Case Details</h3><span>Workflow manager</span></div>
          {selectedIncident ? (
            <div className="panel-list">
              <div className="list-row list-row--pill"><span>ID</span><strong>{selectedIncident.incidentId}</strong></div>
              <div className="list-row list-row--pill"><span>Status</span><strong>{selectedIncident.status}</strong></div>
              <div className="list-row list-row--pill"><span>Owner</span><strong>{selectedIncident.owner?.email || "Unassigned"}</strong></div>
              
              <div style={{ marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <label className="panel-label">Update Status</label>
                <select
                  value={statusDraft}
                  onChange={e => setStatusDraft(e.target.value)}
                  disabled={!isAnalyst}
                >
                  <option value="Open">Open</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Resolved">Resolved</option>
                  <option value="False Positive">False Positive</option>
                </select>
                {user?.role === "admin" ? (
                  <>
                    <label className="panel-label">Assign Owner</label>
                    <select
                      value={ownerDraft}
                      onChange={e => setOwnerDraft(e.target.value)}
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
                <label className="panel-label">Add Note</label>
                <textarea
                  value={noteDraft}
                  onChange={e => setNoteDraft(e.target.value)}
                  placeholder="Type investigation notes..."
                  style={{ minHeight: '80px' }}
                  disabled={!isAnalyst}
                ></textarea>
                <button
                  className="btn-primary"
                  onClick={handleUpdateIncident}
                  disabled={!isAnalyst}
                >
                  Update Case
                </button>
                {!isAnalyst ? (
                  <div style={{ color: 'var(--text-dark)', fontSize: '0.85rem' }}>
                    Incident updates are available to analyst and admin roles.
                  </div>
                ) : null}
              </div>

              <div style={{ marginTop: '30px' }}>
                <h4 className="panel-label" style={{ marginBottom: '12px' }}>Timeline</h4>
                <div style={{ borderLeft: '2px solid var(--border-main)', paddingLeft: '20px', marginLeft: '10px' }}>
                  {selectedIncident.notes?.length ? (
                    selectedIncident.notes.map((entry, idx) => (
                      <div key={idx} style={{ marginBottom: '16px', position: 'relative' }}>
                        <span style={{ position: 'absolute', left: '-26px', top: '4px', width: '10px', height: '10px', borderRadius: '50%', background: 'var(--primary)' }}></span>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>{entry.by?.email || "System"} • {new Date(entry.timestamp || Date.now()).toLocaleTimeString()}</div>
                        <div style={{ marginTop: '4px' }}>{entry.note}</div>
                      </div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-dark)' }}>No notes recorded.</div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dark)' }}>Select an incident to view details</div>
          )}
        </div>
      </div>
    </MainLayout>
  );
};

export default Incidents;
