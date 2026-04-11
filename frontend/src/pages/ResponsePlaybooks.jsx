import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts } from "../services/api";

const playbooks = [
  { id: "block-ip", name: "Block IP", note: "Contain malicious source at firewall or WAF edge.", status: "Investigating" },
  { id: "disable-user", name: "Disable User", note: "Suspend suspicious account activity pending review.", status: "Investigating" },
  { id: "quarantine-asset", name: "Quarantine Asset", note: "Isolate impacted host from production network.", status: "Investigating" },
  { id: "mark-false-positive", name: "Mark False Positive", note: "Close noisy detection after analyst validation.", status: "False Positive" }
];

const ResponsePlaybooks = () => {
  const [alertList, setAlertList] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [history, setHistory] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("threatlens-playbook-history") || "[]");
    } catch {
      return [];
    }
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    localStorage.setItem("threatlens-playbook-history", JSON.stringify(history));
  }, [history]);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        setLoading(true);
        const response = await alerts.list(100, 1);
        const list = response?.data?.data ?? [];
        setAlertList(list);
        setSelectedAlertId(list[0]?._id || "");
      } catch (fetchError) {
        console.error("Playbook alerts error:", fetchError);
        setError("Failed to load alerts");
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();
  }, []);

  const selectedAlert = useMemo(
    () => alertList.find((alert) => alert._id === selectedAlertId),
    [alertList, selectedAlertId]
  );

  const runPlaybook = async (playbook) => {
    if (!selectedAlertId) return;

    try {
      await alerts.update(selectedAlertId, {
        status: playbook.status,
        note: `${playbook.name}: ${playbook.note}`
      });

      setHistory((current) => [
        {
          id: Date.now(),
          playbook: playbook.name,
          alertType: selectedAlert?.type,
          ip: selectedAlert?.ip,
          timestamp: new Date().toISOString()
        },
        ...current
      ]);
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
          <p>Run consistent analyst actions against live alerts and maintain a lightweight execution history.</p>
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
            {playbooks.map((playbook) => (
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
            <span>Local analyst runbook trail</span>
          </div>
          <div className="panel-list">
            {history.length > 0 ? (
              history.map((entry) => (
                <div key={entry.id} className="list-row list-row-stack">
                  <div>
                    <strong>{entry.playbook}</strong>
                    <div className="list-meta">{entry.alertType} / {entry.ip}</div>
                  </div>
                  <span>{new Date(entry.timestamp).toLocaleString()}</span>
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
