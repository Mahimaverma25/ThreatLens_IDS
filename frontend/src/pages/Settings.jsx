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
    theme: "dark",
    notifications: true,
    liveRefresh: true,
  });

  const [idsConfig, setIdsConfig] = useState({
    alertThreshold: 70,
    autoBlock: false,
    severityThreshold: "medium",
    retentionDays: 30,
  });

  const [agentApi, setAgentApi] = useState({
    endpoint: "",
    apiKey: "",
    assetId: "",
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
          theme: data?.system?.theme || "dark",
          notifications: Boolean(data?.system?.notifications ?? true),
          liveRefresh: Boolean(data?.system?.liveRefresh ?? true),
        });

        setIdsConfig({
          alertThreshold: data?.idsConfig?.alertThreshold ?? 70,
          autoBlock: Boolean(data?.idsConfig?.autoBlock ?? false),
          severityThreshold: data?.idsConfig?.severityThreshold || "medium",
          retentionDays: data?.idsConfig?.retentionDays ?? 30,
        });

        setAgentApi({
          endpoint: data?.agentApi?.endpoint || "http://localhost:5000/api",
          apiKey: data?.agentApi?.apiKey || "",
          assetId: data?.agentApi?.assetId || "",
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

    const threshold = Number(idsConfig.alertThreshold);
    if (Number.isNaN(threshold) || threshold < 0 || threshold > 100) {
      return "Alert threshold must be between 0 and 100.";
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

      setProfile({
        name: data?.profile?.name || profile.name,
        email: data?.profile?.email || profile.email,
      });

      setSystem({
        theme: data?.system?.theme || system.theme,
        notifications: Boolean(data?.system?.notifications ?? system.notifications),
        liveRefresh: Boolean(data?.system?.liveRefresh ?? system.liveRefresh),
      });

      setIdsConfig({
        alertThreshold: data?.idsConfig?.alertThreshold ?? idsConfig.alertThreshold,
        autoBlock: Boolean(data?.idsConfig?.autoBlock ?? idsConfig.autoBlock),
        severityThreshold: data?.idsConfig?.severityThreshold || idsConfig.severityThreshold,
        retentionDays: data?.idsConfig?.retentionDays ?? idsConfig.retentionDays,
      });

      setAgentApi({
        endpoint: data?.agentApi?.endpoint || agentApi.endpoint,
        apiKey: data?.agentApi?.apiKey || agentApi.apiKey,
        assetId: data?.agentApi?.assetId || agentApi.assetId,
      });

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

        @media (max-width: 900px) {
          .settings-grid {
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
            <h1>Settings</h1>
            <p>Manage your ThreatLens profile, IDS rules, live monitoring and agent configuration.</p>
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
                  <p className="hint">Update account details used inside the ThreatLens dashboard.</p>

                  <div className="field-group">
                    <label>Name</label>
                    <input
                      type="text"
                      value={profile.name}
                      onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                    />
                  </div>

                  <div className="field-group">
                    <label>Email</label>
                    <input
                      type="email"
                      value={profile.email}
                      onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>Change Password</h3>
                  <p className="hint">Leave these fields empty if you do not want to change your password.</p>

                  <div className="field-group">
                    <label>Current Password</label>
                    <input
                      type="password"
                      value={password.current}
                      onChange={(e) => setPassword({ ...password, current: e.target.value })}
                    />
                  </div>

                  <div className="field-group">
                    <label>New Password</label>
                    <input
                      type="password"
                      value={password.newPass}
                      onChange={(e) => setPassword({ ...password, newPass: e.target.value })}
                    />
                    <span className="strength">Strength: {passwordStrength}</span>
                  </div>

                  <div className="field-group">
                    <label>Confirm New Password</label>
                    <input
                      type="password"
                      value={password.confirmPass}
                      onChange={(e) => setPassword({ ...password, confirmPass: e.target.value })}
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>System Preferences</h3>
                  <p className="hint">Control dashboard appearance and live update behavior.</p>

                  <div className="field-group">
                    <label>Theme</label>
                    <select
                      value={system.theme}
                      onChange={(e) => setSystem({ ...system, theme: e.target.value })}
                    >
                      <option value="dark">Dark</option>
                      <option value="light">Light</option>
                    </select>
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Enable Notifications</strong>
                      <small>Show alert notifications in the dashboard.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={system.notifications}
                      onChange={(e) => setSystem({ ...system, notifications: e.target.checked })}
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <strong>Live Auto Refresh</strong>
                      <small>Allow live pages to refresh logs and alerts automatically.</small>
                    </div>
                    <input
                      type="checkbox"
                      checked={system.liveRefresh}
                      onChange={(e) => setSystem({ ...system, liveRefresh: e.target.checked })}
                    />
                  </div>
                </div>

                <div className="settings-card">
                  <h3>IDS Configuration</h3>
                  <p className="hint">Configure detection sensitivity and response behavior.</p>

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
                        setIdsConfig({ ...idsConfig, severityThreshold: e.target.value })
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
                      <strong>Auto IP Blocking</strong>
                      <small>Automatically block IPs when risk exceeds threshold.</small>
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
                  <h3>Agent / API Settings</h3>
                  <p className="hint">Used by HIDS/NIDS collectors to send telemetry to the backend.</p>

                  <div className="field-group">
                    <label>API Endpoint</label>
                    <input
                      type="text"
                      placeholder="http://localhost:5000/api"
                      value={agentApi.endpoint}
                      onChange={(e) => setAgentApi({ ...agentApi, endpoint: e.target.value })}
                    />
                  </div>

                  <div className="field-group">
                    <label>Agent API Key</label>
                    <input
                      type="text"
                      placeholder="THREATLENS_API_KEY"
                      value={agentApi.apiKey}
                      onChange={(e) => setAgentApi({ ...agentApi, apiKey: e.target.value })}
                    />
                  </div>

                  <div className="field-group">
                    <label>Asset ID</label>
                    <input
                      type="text"
                      placeholder="endpoint-001"
                      value={agentApi.assetId}
                      onChange={(e) => setAgentApi({ ...agentApi, assetId: e.target.value })}
                    />
                  </div>

                  <div className="settings-note">
                    This page saves the values for dashboard configuration. Your actual HIDS/NIDS
                    agent must still use matching values in its `.env` file.
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