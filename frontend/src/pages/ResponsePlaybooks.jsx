import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, playbooks } from "../services/api";

const ResponsePlaybooks = () => {
  const [alertList, setAlertList] = useState([]);
  const [playbookList, setPlaybookList] = useState([]);
  const [history, setHistory] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [runningId, setRunningId] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadData = async () => {
    try {
      setLoading(true);
      setError("");

      const [alertsResponse, playbooksResponse] = await Promise.all([
        alerts.list(100, 1),
        playbooks.list(),
      ]);

      const list = alertsResponse?.data?.data ?? [];
      const playbookData = playbooksResponse?.data?.data?.playbooks ?? [];
      const executions = playbooksResponse?.data?.data?.executions ?? [];

      setAlertList(list);
      setPlaybookList(playbookData);
      setHistory(executions);
      setSelectedAlertId((current) => current || list[0]?._id || "");
    } catch (fetchError) {
      console.error("Playbook load error:", fetchError);
      setError("Failed to load response playbooks");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const selectedAlert = useMemo(
    () => alertList.find((alert) => alert._id === selectedAlertId),
    [alertList, selectedAlertId]
  );

  const metrics = useMemo(() => {
    const criticalAlerts = alertList.filter(
      (alert) => String(alert.severity || "").toLowerCase() === "critical"
    ).length;

    const activeAlerts = alertList.filter(
      (alert) => !["resolved", "closed", "false_positive"].includes(String(alert.status || "").toLowerCase())
    ).length;

    return {
      totalAlerts: alertList.length,
      activeAlerts,
      criticalAlerts,
      playbooks: playbookList.length,
      executions: history.length,
    };
  }, [alertList, playbookList, history]);

  const runPlaybook = async (playbook) => {
    if (!selectedAlertId) {
      setError("Please select an alert before running a playbook.");
      return;
    }

    try {
      setRunningId(playbook.id);
      setError("");

      await playbooks.execute({
        alertId: selectedAlertId,
        playbookId: playbook.id,
      });

      await loadData();
    } catch (runError) {
      console.error("Playbook run error:", runError);
      setError("Failed to execute playbook action");
    } finally {
      setRunningId("");
    }
  };

  const getSeverityClass = (value) => {
    const severity = String(value || "unknown").toLowerCase();
    if (["critical", "high", "medium", "low"].includes(severity)) return severity;
    return "unknown";
  };

  const getStatusClass = (value) => {
    const status = String(value || "new").toLowerCase();
    if (status.includes("resolved")) return "resolved";
    if (status.includes("investigating")) return "investigating";
    if (status.includes("acknowledged")) return "acknowledged";
    if (status.includes("closed")) return "resolved";
    return "new";
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="tl-loading">Loading response playbooks...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="tl-playbooks-page">
        <div className="tl-playbooks-header">
          <div>
            <div className="command-eyebrow">
              THREATLENS / RESPONSE ORCHESTRATION / PLAYBOOKS
            </div>
            <h1>Response Playbooks</h1>
            <p>
              Run predefined analyst actions against live alerts and maintain a backend-tracked response history.
            </p>
          </div>

          <button className="tl-playbooks-refresh" onClick={loadData}>
            Refresh Playbooks
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        <section className="tl-playbooks-summary">
          <div>
            <span>Total Alerts</span>
            <strong>{metrics.totalAlerts}</strong>
          </div>
          <div>
            <span>Active Alerts</span>
            <strong>{metrics.activeAlerts}</strong>
          </div>
          <div>
            <span>Critical Alerts</span>
            <strong>{metrics.criticalAlerts}</strong>
          </div>
          <div>
            <span>Playbooks</span>
            <strong>{metrics.playbooks}</strong>
          </div>
          <div>
            <span>Executions</span>
            <strong>{metrics.executions}</strong>
          </div>
        </section>

        <section className="tl-playbook-panel">
          <div className="tl-playbook-panel-title">
            <h3>▦ Select Alert for Response</h3>
            <span>{alertList.length} alerts available</span>
          </div>

          <div className="tl-playbook-alert-body">
            <div className="tl-form-group">
              <label>Alert</label>
              <select
                value={selectedAlertId}
                onChange={(event) => setSelectedAlertId(event.target.value)}
              >
                {!alertList.length && <option value="">No alerts available</option>}

                {alertList.map((alert) => (
                  <option key={alert._id} value={alert._id}>
                    {alert.type || "Unknown Alert"} / {alert.ip || "Unknown IP"} / {alert.status || "new"}
                  </option>
                ))}
              </select>
            </div>

            {selectedAlert ? (
              <div className="tl-selected-alert-card">
                <div>
                  <span>Current Alert</span>
                  <strong>{selectedAlert.type || "Unknown Alert"}</strong>
                </div>

                <div>
                  <span>Source IP</span>
                  <strong className="tl-playbook-ip">{selectedAlert.ip || "-"}</strong>
                </div>

                <div>
                  <span>Severity</span>
                  <strong className={`tl-playbook-pill ${getSeverityClass(selectedAlert.severity)}`}>
                    {selectedAlert.severity || "unknown"}
                  </strong>
                </div>

                <div>
                  <span>Status</span>
                  <strong className={`tl-playbook-status ${getStatusClass(selectedAlert.status)}`}>
                    {selectedAlert.status || "new"}
                  </strong>
                </div>
              </div>
            ) : (
              <div className="tl-playbook-empty">
                No alert selected. Generate or ingest alerts first.
              </div>
            )}
          </div>
        </section>

        <section className="tl-playbook-grid">
          <div className="tl-playbook-panel">
            <div className="tl-playbook-panel-title">
              <h3>▦ Operational Playbooks</h3>
              <span>{playbookList.length} templates</span>
            </div>

            <div className="tl-playbook-list">
              {playbookList.map((playbook) => (
                <div key={playbook.id} className="tl-playbook-card">
                  <div>
                    <h4>{playbook.name}</h4>
                    <p>{playbook.note}</p>
                    <small>Action ID: {playbook.id}</small>
                  </div>

                  <button
                    className="tl-run-playbook-btn"
                    disabled={!selectedAlertId || runningId === playbook.id}
                    onClick={() => runPlaybook(playbook)}
                  >
                    {runningId === playbook.id ? "Running..." : "Run"}
                  </button>
                </div>
              ))}

              {!playbookList.length && (
                <div className="tl-playbook-empty">
                  No response playbooks configured.
                </div>
              )}
            </div>
          </div>

          <div className="tl-playbook-panel">
            <div className="tl-playbook-panel-title">
              <h3>▦ Execution History</h3>
              <span>{history.length} records</span>
            </div>

            <div className="tl-playbook-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Playbook</th>
                    <th>Alert / IP</th>
                    <th>Executed At</th>
                  </tr>
                </thead>

                <tbody>
                  {history.map((entry) => (
                    <tr key={entry._id}>
                      <td>{entry.playbook_name || "Unknown Playbook"}</td>
                      <td>
                        <span>
                          {entry.metadata?.alertType || entry.alert_id?.type || "Alert"}
                        </span>
                        <small className="tl-playbook-ip">
                          {entry.metadata?.ip || entry.alert_id?.ip || "-"}
                        </small>
                      </td>
                      <td>
                        {entry.createdAt
                          ? new Date(entry.createdAt).toLocaleString()
                          : "-"}
                      </td>
                    </tr>
                  ))}

                  {!history.length && (
                    <tr>
                      <td colSpan="3" className="tl-playbook-empty-cell">
                        No playbooks have been executed yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </section>
    </MainLayout>
  );
};

export default ResponsePlaybooks;