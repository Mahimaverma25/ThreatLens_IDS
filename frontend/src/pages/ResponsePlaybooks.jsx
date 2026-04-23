import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, playbooks } from "../services/api";

const ResponsePlaybooks = () => {
  const [alertList, setAlertList] = useState([]);
  const [playbookList, setPlaybookList] = useState([]);
  const [history, setHistory] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState("");
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

  const runPlaybook = async (playbook) => {
    if (!selectedAlertId) return;

    try {
      setError("");
      await playbooks.execute({
        alertId: selectedAlertId,
        playbookId: playbook.id,
      });
      await loadData();
    } catch (runError) {
      console.error("Playbook run error:", runError);
      setError("Failed to execute playbook action");
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading response playbooks...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Response orchestration / analyst actions</div>
          <h1>Response Playbooks</h1>
          <p>Run backend-tracked analyst actions against live alerts and maintain an execution history.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <div className="card">
        <h3>Select Alert</h3>
        <div className="action-row">
          <select value={selectedAlertId} onChange={(event) => setSelectedAlertId(event.target.value)}>
            {alertList.map((alert) => (
              <option key={alert._id} value={alert._id}>
                {alert.type} / {alert.ip} / {alert.status}
              </option>
            ))}
          </select>
        </div>
        {selectedAlert && (
          <div className="generated-secret">
            <div><strong>Current Alert:</strong> {selectedAlert.type}</div>
            <div><strong>Source:</strong> <span className="mono-text">{selectedAlert.ip}</span></div>
            <div><strong>Severity:</strong> {selectedAlert.severity}</div>
            <div><strong>Status:</strong> {selectedAlert.status}</div>
          </div>
        )}
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Playbooks</h3>
            <span>Operational response templates</span>
          </div>
          <div className="panel-list">
            {playbookList.map((playbook) => (
              <div key={playbook.id} className="list-row list-row-stack">
                <div>
                  <strong>{playbook.name}</strong>
                  <div className="list-meta">{playbook.note}</div>
                </div>
                <button className="scan-btn" onClick={() => runPlaybook(playbook)}>
                  Run
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Execution History</h3>
            <span>Backend-tracked analyst runbook trail</span>
          </div>
          <div className="panel-list">
            {history.length > 0 ? (
              history.map((entry) => (
                <div key={entry._id} className="list-row list-row-stack">
                  <div>
                    <strong>{entry.playbook_name}</strong>
                    <div className="list-meta">
                      {entry.metadata?.alertType || entry.alert_id?.type} / {entry.metadata?.ip || entry.alert_id?.ip}
                    </div>
                  </div>
                  <span>{entry.createdAt ? new Date(entry.createdAt).toLocaleString() : "-"}</span>
                </div>
              ))
            ) : (
              <p>No playbooks have been run yet.</p>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default ResponsePlaybooks;
