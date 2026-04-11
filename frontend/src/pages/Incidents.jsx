import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";

const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const Incidents = () => {
  const [incidentRows, setIncidentRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await alerts.list(200, 1);
        const list = response?.data?.data ?? [];
        const grouped = new Map();

        list.forEach((alert) => {
          const key = `${alert.attackType || alert.type}-${alert.ip}`;
          const existing = grouped.get(key) || {
            id: key,
            attackType: alert.attackType || alert.type,
            ip: alert.ip,
            totalAlerts: 0,
            severity: alert.severity || "Low",
            status: alert.status || "New",
            firstSeen: alert.timestamp,
            lastSeen: alert.timestamp,
            leadAlertId: alert._id,
            confidenceTotal: 0,
            riskTotal: 0
          };

          existing.totalAlerts += 1;
          existing.confidenceTotal += Number(alert.confidence || 0);
          existing.riskTotal += Number(alert.risk_score || 0);

          if (severityRank[alert.severity] > severityRank[existing.severity]) {
            existing.severity = alert.severity;
          }

          if (new Date(alert.timestamp) > new Date(existing.lastSeen)) {
            existing.lastSeen = alert.timestamp;
            existing.status = alert.status || existing.status;
            existing.leadAlertId = alert._id;
          }

          if (new Date(alert.timestamp) < new Date(existing.firstSeen)) {
            existing.firstSeen = alert.timestamp;
          }

          grouped.set(key, existing);
        });

        setIncidentRows(
          [...grouped.values()]
            .map((incident) => ({
              ...incident,
              avgConfidence: Math.round((incident.confidenceTotal / incident.totalAlerts) * 100),
              avgRisk: Math.round(incident.riskTotal / incident.totalAlerts)
            }))
            .sort((left, right) => new Date(right.lastSeen) - new Date(left.lastSeen))
        );
      } catch (fetchError) {
        console.error("Incident fetch error:", fetchError);
        setError("Failed to build incident groups");
      } finally {
        setLoading(false);
      }
    };

    fetchIncidents();
  }, []);

  const overview = useMemo(() => {
    return incidentRows.reduce(
      (accumulator, incident) => {
        accumulator.total += 1;
        if (incident.status === "Investigating") accumulator.investigating += 1;
        if (incident.severity === "Critical") accumulator.critical += 1;
        accumulator.linkedAlerts += incident.totalAlerts;
        return accumulator;
      },
      { total: 0, investigating: 0, critical: 0, linkedAlerts: 0 }
    );
  }, [incidentRows]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Building incident timeline...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Incident correlation / timeline</div>
          <h1>Incidents</h1>
          <p>Grouped investigations built from repeated alerts against the same threat pattern and source.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Incident Groups</span>
          <strong>{overview.total}</strong>
        </div>
        <div className="metric-card">
          <span>Investigating</span>
          <strong>{overview.investigating}</strong>
        </div>
        <div className="metric-card">
          <span>Critical Incidents</span>
          <strong>{overview.critical}</strong>
        </div>
        <div className="metric-card">
          <span>Linked Alerts</span>
          <strong>{overview.linkedAlerts}</strong>
        </div>
      </section>

      <div className="card">
        {incidentRows.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Incident</th>
                <th>IP</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Alerts</th>
                <th>Avg Confidence</th>
                <th>Avg Risk</th>
                <th>First Seen</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {incidentRows.map((incident) => (
                <tr key={incident.id}>
                  <td>
                    <Link className="alert-link" to={`/alerts/${incident.leadAlertId}`}>
                      {incident.attackType}
                    </Link>
                  </td>
                  <td className="mono-text">{incident.ip}</td>
                  <td>{incident.severity}</td>
                  <td>{incident.status}</td>
                  <td>{incident.totalAlerts}</td>
                  <td>{incident.avgConfidence}%</td>
                  <td>{incident.avgRisk}</td>
                  <td>{incident.firstSeen ? new Date(incident.firstSeen).toLocaleString() : "-"}</td>
                  <td>{incident.lastSeen ? new Date(incident.lastSeen).toLocaleString() : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No incidents have been grouped yet.</p>
        )}
      </div>
    </MainLayout>
  );
};

export default Incidents;
