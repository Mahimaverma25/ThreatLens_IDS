import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { useAuth } from "../context/AuthContext";
import { settings as settingsApi } from "../services/api";

const Settings = () => {
  const { user, updateUser } = useAuth();

  const [profile, setProfile] = useState({ name: "", email: "" });
  const [password, setPassword] = useState({
    current: "",
    newPass: "",
    confirmPass: "",
  });

  const [system, setSystem] = useState({
    notifications: true,
    liveRefresh: true,
    criticalAlerts: true,
    incidentEscalation: true,
  });

  const [idsConfig, setIdsConfig] = useState({
    detectionMode: "hybrid",
    alertThreshold: 70,
    severityThreshold: "medium",
    autoIncident: true,
    autoBlock: false,
    retentionDays: 30,
  });

  const [mlConfig, setMlConfig] = useState({
    randomForest: true,
    anomalyDetection: true,
    confidenceThreshold: 85,
    datasetVersion: "CICIDS2017",
    autoRetraining: false,
  });

  const [agentApi, setAgentApi] = useState({
    endpoint: "",
    apiKey: "",
    assetId: "",
    snortStatus: "connected",
    socketStatus: "active",
    idsEngineStatus: "operational",
  });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [error, setError] = useState("");

  const passwordStrength = useMemo(() => {
    const value = password.newPass;
    if (!value) return "Not changed";
    if (value.length < 6) return "Weak";
    if (value.length < 10) return "Medium";
    return "Strong";
  }, [password.newPass]);

  useEffect(() => {
    const loadSettings = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await settingsApi.get();
        const data = response?.data?.data || {};

        setProfile({
          name: data?.profile?.name || user?.name || "",
          email: data?.profile?.email || user?.email || "",
        });

        setSystem({
          notifications: Boolean(data?.system?.notifications ?? true),
          liveRefresh: Boolean(data?.system?.liveRefresh ?? true),
          criticalAlerts: Boolean(data?.system?.criticalAlerts ?? true),
          incidentEscalation: Boolean(data?.system?.incidentEscalation ?? true),
        });

        setIdsConfig({
          detectionMode: data?.idsConfig?.detectionMode || "hybrid",
          alertThreshold: data?.idsConfig?.alertThreshold ?? 70,
          severityThreshold: data?.idsConfig?.severityThreshold || "medium",
          autoIncident: Boolean(data?.idsConfig?.autoIncident ?? true),
          autoBlock: Boolean(data?.idsConfig?.autoBlock ?? false),
          retentionDays: data?.idsConfig?.retentionDays ?? 30,
        });

        setMlConfig({
          randomForest: Boolean(data?.mlConfig?.randomForest ?? true),
          anomalyDetection: Boolean(data?.mlConfig?.anomalyDetection ?? true),
          confidenceThreshold: data?.mlConfig?.confidenceThreshold ?? 85,
          datasetVersion: data?.mlConfig?.datasetVersion || "CICIDS2017",
          autoRetraining: Boolean(data?.mlConfig?.autoRetraining ?? false),
        });

        setAgentApi({
          endpoint: data?.agentApi?.endpoint || "http://localhost:5000/api",
          apiKey: data?.agentApi?.apiKey || "",
          assetId: data?.agentApi?.assetId || "",
          snortStatus: data?.agentApi?.snortStatus || "connected",
          socketStatus: data?.agentApi?.socketStatus || "active",
          idsEngineStatus: data?.agentApi?.idsEngineStatus || "operational",
        });
      } catch (err) {
        setError(err?.response?.data?.message || "Failed to load settings.");
      } finally {
        setLoading(false);
      }
    };

    loadSettings();
  }, [user]);

  const validateBeforeSave = () => {
    if (!profile.name.trim()) return "Name is required.";
    if (!profile.email.trim()) return "Email is required.";

    if (password.newPass || password.current || password.confirmPass) {
      if (!password.current) return "Current password is required.";
      if (password.newPass.length < 6) return "New password must be at least 6 characters.";
      if (password.newPass !== password.confirmPass) return "New password and confirm password do not match.";
    }

    const alertThreshold = Number(idsConfig.alertThreshold);
    if (Number.isNaN(alertThreshold) || alertThreshold < 0 || alertThreshold > 100) {
      return "Alert threshold must be between 0 and 100.";
    }

    const confidenceThreshold = Number(mlConfig.confidenceThreshold);
    if (Number.isNaN(confidenceThreshold) || confidenceThreshold < 0 || confidenceThreshold > 100) {
      return "ML confidence threshold must be between 0 and 100.";
    }

    const retention = Number(idsConfig.retentionDays);
    if (Number.isNaN(retention) || retention < 1) {
      return "Retention days must be at least 1.";
    }

    return "";
  };

  const handleSave = async () => {
    const validationError = validateBeforeSave();

    if (validationError) {
      setError(validationError);
      setFeedback("");
      return;
    }

    try {
      setSaving(true);
      setError("");
      setFeedback("");

      const payload = {
        profile,
        system,
        idsConfig: {
          ...idsConfig,
          alertThreshold: Number(idsConfig.alertThreshold),
          retentionDays: Number(idsConfig.retentionDays),
        },
        mlConfig: {
          ...mlConfig,
          confidenceThreshold: Number(mlConfig.confidenceThreshold),
        },
        agentApi,
      };

      if (password.current && password.newPass) {
        payload.password = {
          current: password.current,
          newPass: password.newPass,
        };
      }

      const response = await settingsApi.update(payload);
      const data = response?.data?.data || {};

      if (data?.user) updateUser(data.user);

      setPassword({ current: "", newPass: "", confirmPass: "" });
      setFeedback(response?.data?.message || "Settings saved successfully.");
    } catch (err) {
      setError(err?.response?.data?.message || "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <MainLayout>
      <style>{`
        .settings-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background: linear-gradient(135deg, #fff7ed 0%, #f8fbff 55%, #eef9f1 100%);
        }

        .settings-shell {
          max-width: 1180px;
          margin: 0 auto;
        }

        .settings-header {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 24px;
          padding: 30px;
          margin-bottom: 24px;
          box-shadow: 0 18px 45px rgba(15,23,42,.08);
        }

        .settings-header h1 {
          margin: 0;
          font-size: 34px;
          color: #0f2742;
        }

        .settings-header p {
          margin: 10px 0 0;
          color: #64748b;
        }

        .settings-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 22px;
        }

        .settings-card {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 22px;
          padding: 24px;
          box-shadow: 0 16px 38px rgba(15,23,42,.07);
        }

        .settings-card h3 {
          margin: 0 0 6px;
          color: #172033;
          font-size: 20px;
        }

        .settings-card .hint {
          margin: 0 0 18px;
          color: #64748b;
          font-size: 13px;
          line-height: 1.6;
        }

        .field-group {
          display: grid;
          gap: 10px;
          margin-bottom: 16px;
        }

        .field-group label {
          font-size: 13px;
          font-weight: 900;
          color: #334155;
        }

        .field-group input,
        .field-group select {
          width: 100%;
          border: 1px solid #dbe3ef;
          background: #f8fbff;
          border-radius: 14px;
          padding: 13px 14px;
          outline: none;
          color: #172033;
          font-size: 14px;
        }

        .field-group input:focus,
        .field-group select:focus {
          border-color: #0ea5e9;
          box-shadow: 0 0 0 4px rgba(14,165,233,.12);
          background: #fff;
        }

        .toggle-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 14px;
          padding: 14px;
          background: #f8fbff;
          border: 1px solid #e2e8f0;
          border-radius: 16px;
          margin-bottom: 14px;
        }

        .toggle-row strong {
          display: block;
          color: #172033;
          font-size: 14px;
        }

        .toggle-row small {
          color: #64748b;
        }

        .toggle-row input {
          width: 20px;
          height: 20px;
          accent-color: #0ea5e9;
        }

        .settings-actions {
          margin-top: 24px;
          display: flex;
          justify-content: flex-end;
          gap: 14px;
        }

        .primary-btn {
          border: 0;
          border-radius: 14px;
          padding: 14px 24px;
          font-weight: 900;
          color: #fff;
          cursor: pointer;
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
          box-shadow: 0 12px 26px rgba(37,99,235,.22);
        }

        .primary-btn:disabled {
          opacity: .6;
          cursor: not-allowed;
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

        .strength {
          font-size: 12px;
          color: #64748b;
          font-weight: 800;
        }

        .settings-note {
          margin-top: 14px;
          padding: 14px;
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          border-radius: 14px;
          color: #1e3a8a;
          font-size: 13px;
          line-height: 1.6;
        }

        .status-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 12px;
          margin-top: 14px;
        }

        .status-chip {
          padding: 14px;
          border-radius: 14px;
          background: #f8fbff;
          border: 1px solid #e2e8f0;
        }

        .status-chip span {
          display: block;
          color: #64748b;
          font-size: 12px;
          font-weight: 800;
        }

        .status-chip strong {
          display: block;
          margin-top: 6px;
          color: #047857;
          font-size: 14px;
          text-transform: capitalize;
        }

        @media (max-width: 900px) {
          .settings-grid,
          .status-grid {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 620px) {
          .settings-page {
            padding: 16px;
          }

          .settings-header {
            padding: 24px;
          }

          .settings-header h1 {
            font-size: 28px;
          }

          .settings-actions {
            flex-direction: column;
          }

          .primary-btn {
            width: 100%;
          }
        }
      `}</style>

      <div className="settings-page">
        <div className="settings-shell">
          <div className="settings-header">
            <h1>ThreatLens Settings</h1>
            <p>
              Manage SOC configuration, IDS behavior, ML detection parameters,
              live monitoring, and secure agent connectivity.
            </p>
          </div>

          {error ? <div className="error-message">{error}</div> : null}
          {feedback ? <div className="success-message">{feedback}</div> : null}

          {loading ? (
            <div className="loading">Loading settings...</div>
          ) : (
            <>
              <div className="settings-grid">
                <div className="settings-card">
                  <h3>User Profile</h3>
                  <p className="hint">
                    Account details used inside the ThreatLens SOC dashboard.
                  </p>

                  <div className="field-group">
                    <label>Name</label>
                    <input
                      type="text"
                      value={profile.name}
                      onChange={(e) =>
                        setProfile({ ...profile, name: e.target.value })
                      }
                    />
                  </div>

                  <div className="field-group">
                    <label>Email</label>
                    <input
                      type="email"
                      value={profile.email}
                      onChange={(e) =>
                        setProfile({ ...profile, email: e.target.value })
                      }
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>Change Password</h3>
                  <p className="hint">
                    Keep your analyst/admin account secure.
                  </p>

                  <div className="field-group">
                    <label>Current Password</label>
                    <input
                      type="password"
                      value={password.current}
                      onChange={(e) =>
                        setPassword({ ...password, current: e.target.value })
                      }
                    />
                  </div>

                  <div className="field-group">
                    <label>New Password</label>
                    <input
                      type="password"
                      value={password.newPass}
                      onChange={(e) =>
                        setPassword({ ...password, newPass: e.target.value })
                      }
                    />
                    <span className="strength">Strength: {passwordStrength}</span>
                  </div>

                  <div className="field-group">
                    <label>Confirm New Password</label>
                    <input
                      type="password"
                      value={password.confirmPass}
                      onChange={(e) =>
                        setPassword({ ...password, confirmPass: e.target.value })
                      }
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>Security Operations</h3>
                  <p className="hint">
                    Controls alert notifications, escalation, and real-time SOC behavior.
                  </p>

                  <div className="toggle-row">
                    <div>
                      <strong>Critical Alert Notifications</strong>
                      <small>Show priority notifications for critical alerts.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={system.criticalAlerts}
                      onChange={(e) =>
                        setSystem({ ...system, criticalAlerts: e.target.checked })
                      }
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Live Auto Refresh</strong>
                      <small>Automatically refresh logs, alerts, and dashboard signals.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={system.liveRefresh}
                      onChange={(e) =>
                        setSystem({ ...system, liveRefresh: e.target.checked })
                      }
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Incident Escalation</strong>
                      <small>Create incident workflow for high-risk detections.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={system.incidentEscalation}
                      onChange={(e) =>
                        setSystem({ ...system, incidentEscalation: e.target.checked })
                      }
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>IDS Configuration</h3>
                  <p className="hint">
                    Configure hybrid detection, severity threshold, retention, and response behavior.
                  </p>

                  <div className="field-group">
                    <label>Detection Engine Mode</label>
                    <select
                      value={idsConfig.detectionMode}
                      onChange={(e) =>
                        setIdsConfig({ ...idsConfig, detectionMode: e.target.value })
                      }
                    >
                      <option value="hybrid">Hybrid Detection - Snort + ML</option>
                      <option value="rules">Rule-Based Detection Only</option>
                      <option value="ml">ML-Assisted Detection</option>
                    </select>
                  </div>

                  <div className="field-group">
                    <label>Alert Threshold (%)</label>
                    <input
                      type="number"
                      min="0"
                      max="100"
                      value={idsConfig.alertThreshold}
                      onChange={(e) =>
                        setIdsConfig({ ...idsConfig, alertThreshold: e.target.value })
                      }
                    />
                  </div>

                  <div className="field-group">
                    <label>Minimum Severity</label>
                    <select
                      value={idsConfig.severityThreshold}
                      onChange={(e) =>
                        setIdsConfig({
                          ...idsConfig,
                          severityThreshold: e.target.value,
                        })
                      }
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>

                  <div className="field-group">
                    <label>Log Retention Days</label>
                    <input
                      type="number"
                      min="1"
                      value={idsConfig.retentionDays}
                      onChange={(e) =>
                        setIdsConfig({ ...idsConfig, retentionDays: e.target.value })
                      }
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Auto Incident Generation</strong>
                      <small>Generate incidents automatically for high-risk alerts.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={idsConfig.autoIncident}
                      onChange={(e) =>
                        setIdsConfig({ ...idsConfig, autoIncident: e.target.checked })
                      }
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Auto IP Blocking</strong>
                      <small>Block IPs automatically when risk crosses threshold.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={idsConfig.autoBlock}
                      onChange={(e) =>
                        setIdsConfig({ ...idsConfig, autoBlock: e.target.checked })
                      }
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>Machine Learning Engine</h3>
                  <p className="hint">
                    Configure Random Forest, anomaly detection, and prediction confidence.
                  </p>

                  <div className="toggle-row">
                    <div>
                      <strong>Random Forest Model</strong>
                      <small>Enable supervised attack classification.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={mlConfig.randomForest}
                      onChange={(e) =>
                        setMlConfig({ ...mlConfig, randomForest: e.target.checked })
                      }
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Anomaly Detection</strong>
                      <small>Enable suspicious behavior detection for unknown patterns.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={mlConfig.anomalyDetection}
                      onChange={(e) =>
                        setMlConfig({
                          ...mlConfig,
                          anomalyDetection: e.target.checked,
                        })
                      }
                    />
                  </div>

                  <div className="field-group">
                    <label>Model Confidence Threshold (%)</label>
                    <input
                      type="number"
                      min="0"
                      max="100"
                      value={mlConfig.confidenceThreshold}
                      onChange={(e) =>
                        setMlConfig({
                          ...mlConfig,
                          confidenceThreshold: e.target.value,
                        })
                      }
                    />
                  </div>

                  <div className="field-group">
                    <label>Dataset Version</label>
                    <input
                      type="text"
                      value={mlConfig.datasetVersion}
                      onChange={(e) =>
                        setMlConfig({ ...mlConfig, datasetVersion: e.target.value })
                      }
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Auto Retraining</strong>
                      <small>Disabled by default for controlled academic evaluation.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={mlConfig.autoRetraining}
                      onChange={(e) =>
                        setMlConfig({ ...mlConfig, autoRetraining: e.target.checked })
                      }
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>Agent / API Settings</h3>
                  <p className="hint">
                    Used by HIDS/NIDS collectors to send telemetry to the backend.
                  </p>

                  <div className="field-group">
                    <label>API Endpoint</label>
                    <input
                      type="text"
                      placeholder="http://localhost:5000/api"
                      value={agentApi.endpoint}
                      onChange={(e) =>
                        setAgentApi({ ...agentApi, endpoint: e.target.value })
                      }
                    />
                  </div>

                  <div className="field-group">
                    <label>Agent API Key</label>
                    <input
                      type="text"
                      placeholder="THREATLENS_API_KEY"
                      value={agentApi.apiKey}
                      onChange={(e) =>
                        setAgentApi({ ...agentApi, apiKey: e.target.value })
                      }
                    />
                  </div>

                  <div className="field-group">
                    <label>Asset ID</label>
                    <input
                      type="text"
                      placeholder="endpoint-001"
                      value={agentApi.assetId}
                      onChange={(e) =>
                        setAgentApi({ ...agentApi, assetId: e.target.value })
                      }
                    />
                  </div>

                  <div className="status-grid">
                    <div className="status-chip">
                      <span>Snort Integration</span>
                      <strong>{agentApi.snortStatus}</strong>
                    </div>
                    <div className="status-chip">
                      <span>Socket.IO Stream</span>
                      <strong>{agentApi.socketStatus}</strong>
                    </div>
                    <div className="status-chip">
                      <span>IDS Engine</span>
                      <strong>{agentApi.idsEngineStatus}</strong>
                    </div>
                  </div>

                  <div className="settings-note">
                    This page stores dashboard configuration. The actual HIDS/NIDS agent must still use matching values inside its `.env` file.
                  </div>
                </div>
              </div>

              <div className="settings-actions">
                <button className="primary-btn" onClick={handleSave} disabled={saving}>
                  {saving ? "Saving..." : "Save Settings"}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </MainLayout>
  );
};

export default Settings;