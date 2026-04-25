import { useEffect, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { useAuth } from "../context/AuthContext";
import { settings as settingsApi } from "../services/api";

const Settings = () => {
  const { updateUser } = useAuth();

  const [profile, setProfile] = useState({
    name: "",
    email: "",
  });

  const [password, setPassword] = useState({
    current: "",
    newPass: "",
  });

  const [system, setSystem] = useState({
    theme: "dark",
    notifications: true,
  });

  const [idsConfig, setIdsConfig] = useState({
    alertThreshold: 70,
    autoBlock: false,
  });

  const [agentApi, setAgentApi] = useState({
    endpoint: "",
    apiKey: "",
  });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const loadSettings = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await settingsApi.get();
        const data = response?.data?.data || {};

        setProfile({
          name: data?.profile?.name || "",
          email: data?.profile?.email || "",
        });
        setSystem({
          theme: data?.system?.theme || "dark",
          notifications: Boolean(data?.system?.notifications ?? true),
        });
        setIdsConfig({
          alertThreshold: data?.idsConfig?.alertThreshold ?? 70,
          autoBlock: Boolean(data?.idsConfig?.autoBlock ?? false),
        });
        setAgentApi({
          endpoint: data?.agentApi?.endpoint || "",
          apiKey: data?.agentApi?.apiKey || "",
        });
      } catch (err) {
        setError(err?.response?.data?.message || "Failed to load settings.");
      } finally {
        setLoading(false);
      }
    };

    loadSettings();
  }, []);

  const handleSave = async () => {
    try {
      setSaving(true);
      setError("");
      setFeedback("");

      const response = await settingsApi.update({
        profile,
        password,
        system,
        idsConfig: {
          ...idsConfig,
          alertThreshold: Number(idsConfig.alertThreshold),
        },
        agentApi,
      });

      const data = response?.data?.data || {};

      if (data?.user) {
        updateUser(data.user);
      }

      setProfile({
        name: data?.profile?.name || "",
        email: data?.profile?.email || "",
      });
      setSystem({
        theme: data?.system?.theme || "dark",
        notifications: Boolean(data?.system?.notifications ?? true),
      });
      setIdsConfig({
        alertThreshold: data?.idsConfig?.alertThreshold ?? 70,
        autoBlock: Boolean(data?.idsConfig?.autoBlock ?? false),
      });
      setAgentApi({
        endpoint: data?.agentApi?.endpoint || "",
        apiKey: data?.agentApi?.apiKey || "",
      });
      setPassword({
        current: "",
        newPass: "",
      });
      setFeedback(response?.data?.message || "Settings saved successfully.");
    } catch (err) {
      setError(err?.response?.data?.message || "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <MainLayout>
      <div className="settings-page">
        <div className="settings-header">
          <h1>Settings</h1>
          <p>Manage your ThreatLens system configuration</p>
        </div>

        {error ? <div className="error-message">{error}</div> : null}
        {feedback ? <div className="generated-secret">{feedback}</div> : null}

        {loading ? (
          <div className="loading">Loading settings...</div>
        ) : (
          <>
            <div className="settings-grid">
              <div className="settings-card">
                <h3>User Profile</h3>

                <label>Name</label>
                <input
                  type="text"
                  value={profile.name}
                  onChange={(e) =>
                    setProfile({ ...profile, name: e.target.value })
                  }
                />

                <label>Email</label>
                <input
                  type="email"
                  value={profile.email}
                  onChange={(e) =>
                    setProfile({ ...profile, email: e.target.value })
                  }
                />
              </div>

              <div className="settings-card">
                <h3>Change Password</h3>

                <label>Current Password</label>
                <input
                  type="password"
                  value={password.current}
                  onChange={(e) =>
                    setPassword({ ...password, current: e.target.value })
                  }
                />

                <label>New Password</label>
                <input
                  type="password"
                  value={password.newPass}
                  onChange={(e) =>
                    setPassword({ ...password, newPass: e.target.value })
                  }
                />
              </div>

              <div className="settings-card">
                <h3>System Preferences</h3>

                <label>Theme</label>
                <select
                  value={system.theme}
                  onChange={(e) =>
                    setSystem({ ...system, theme: e.target.value })
                  }
                >
                  <option value="dark">Dark</option>
                  <option value="light">Light</option>
                </select>

                <label>
                  <input
                    type="checkbox"
                    checked={system.notifications}
                    onChange={(e) =>
                      setSystem({ ...system, notifications: e.target.checked })
                    }
                  />
                  Enable Notifications
                </label>
              </div>

              <div className="settings-card">
                <h3>IDS Configuration</h3>

                <label>Alert Threshold (%)</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={idsConfig.alertThreshold}
                  onChange={(e) =>
                    setIdsConfig({
                      ...idsConfig,
                      alertThreshold: e.target.value,
                    })
                  }
                />

                <label>
                  <input
                    type="checkbox"
                    checked={idsConfig.autoBlock}
                    onChange={(e) =>
                      setIdsConfig({
                        ...idsConfig,
                        autoBlock: e.target.checked,
                      })
                    }
                  />
                  Enable Auto IP Blocking
                </label>
              </div>

              <div className="settings-card">
                <h3>Agent / API Settings</h3>

                <label>API Endpoint</label>
                <input
                  type="text"
                  placeholder="http://localhost:5000/api"
                  value={agentApi.endpoint}
                  onChange={(e) =>
                    setAgentApi({ ...agentApi, endpoint: e.target.value })
                  }
                />

                <label>API Key</label>
                <input
                  type="text"
                  placeholder="Your API Key"
                  value={agentApi.apiKey}
                  onChange={(e) =>
                    setAgentApi({ ...agentApi, apiKey: e.target.value })
                  }
                />
              </div>
            </div>

            <div className="settings-actions">
              <button
                className="primary-btn"
                onClick={handleSave}
                disabled={saving}
              >
                {saving ? "Saving..." : "Save Settings"}
              </button>
            </div>
          </>
        )}
      </div>
    </MainLayout>
  );
};

export default Settings;
