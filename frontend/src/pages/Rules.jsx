import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";

const storageKey = "threatlens-rule-profile";

const defaultRules = [
  {
    id: "bruteforce-login",
    name: "Brute Force Login Attempts",
    detector: "Node correlator",
    threshold: "5 failed logins / 10 min",
    severity: "High",
    enabled: true
  },
  {
    id: "request-burst",
    name: "Request Burst / DoS",
    detector: "Node correlator",
    threshold: "150 requests / minute",
    severity: "Critical",
    enabled: true
  },
  {
    id: "admin-access",
    name: "Unauthorized Admin Access",
    detector: "Node correlator",
    threshold: "Any denied admin access",
    severity: "Critical",
    enabled: true
  },
  {
    id: "suspicious-ip",
    name: "Suspicious IP Activity",
    detector: "Node correlator",
    threshold: "10 distinct endpoints / 10 min",
    severity: "Medium",
    enabled: true
  },
  {
    id: "ids-ddos",
    name: "Possible DDoS Attack",
    detector: "Python IDS rules",
    threshold: "Packets > 300",
    severity: "High",
    enabled: true
  },
  {
    id: "ids-ssh",
    name: "Brute Force SSH Attempt",
    detector: "Python IDS rules",
    threshold: "Port 22 and packets > 100",
    severity: "Medium",
    enabled: true
  },
  {
    id: "anomaly",
    name: "Anomalous Traffic",
    detector: "attack_model.pkl",
    threshold: "ML classification on packets + port",
    severity: "High",
    enabled: true
  }
];

const Rules = () => {
  const [rules, setRules] = useState(defaultRules);

  useEffect(() => {
    const saved = localStorage.getItem(storageKey);
    if (saved) {
      try {
        setRules(JSON.parse(saved));
      } catch (error) {
        console.error("Failed to restore rule profile", error);
      }
    }
  }, []);

  useEffect(() => {
    localStorage.setItem(storageKey, JSON.stringify(rules));
  }, [rules]);

  const summary = useMemo(() => {
    return rules.reduce(
      (accumulator, rule) => {
        accumulator.total += 1;
        if (rule.enabled) accumulator.enabled += 1;
        if (rule.detector.includes("Node")) accumulator.node += 1;
        if (rule.detector.includes("Python") || rule.detector.includes("attack_model")) accumulator.ids += 1;
        return accumulator;
      },
      { total: 0, enabled: 0, node: 0, ids: 0 }
    );
  }, [rules]);

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Detection policies / tuning workspace</div>
          <h1>Rules</h1>
          <p>Review the active detection logic and maintain a staged tuning profile for future backend rule management.</p>
        </div>
      </section>

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Total Rules</span>
          <strong>{summary.total}</strong>
        </div>
        <div className="metric-card">
          <span>Enabled</span>
          <strong>{summary.enabled}</strong>
        </div>
        <div className="metric-card">
          <span>Node Correlators</span>
          <strong>{summary.node}</strong>
        </div>
        <div className="metric-card">
          <span>IDS / ML Rules</span>
          <strong>{summary.ids}</strong>
        </div>
      </section>

      <div className="card">
        <h3>Detection Rulebook</h3>
        <div className="panel-list">
          {rules.map((rule) => (
            <div key={rule.id} className="list-row list-row-stack">
              <div>
                <strong>{rule.name}</strong>
                <div className="list-meta">{rule.detector}</div>
              </div>
              <div className="rule-controls">
                <input
                  value={rule.threshold}
                  onChange={(event) =>
                    setRules((current) =>
                      current.map((item) =>
                        item.id === rule.id ? { ...item, threshold: event.target.value } : item
                      )
                    )
                  }
                />
                <select
                  value={rule.severity}
                  onChange={(event) =>
                    setRules((current) =>
                      current.map((item) =>
                        item.id === rule.id ? { ...item, severity: event.target.value } : item
                      )
                    )
                  }
                >
                  <option value="Low">Low</option>
                  <option value="Medium">Medium</option>
                  <option value="High">High</option>
                  <option value="Critical">Critical</option>
                </select>
                <button
                  className={rule.enabled ? "ghost-btn" : "scan-btn"}
                  onClick={() =>
                    setRules((current) =>
                      current.map((item) =>
                        item.id === rule.id ? { ...item, enabled: !item.enabled } : item
                      )
                    )
                  }
                >
                  {rule.enabled ? "Enabled" : "Disabled"}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </MainLayout>
  );
};

export default Rules;
