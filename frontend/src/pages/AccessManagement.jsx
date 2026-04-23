import { useCallback, useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { apiKeys, assets, users } from "../services/api";
import { useAuth } from "../context/AuthContext";

const AccessManagement = () => {
  const { user } = useAuth();
  const [userList, setUserList] = useState([]);
  const [keyList, setKeyList] = useState([]);
  const [assetList, setAssetList] = useState([]);
  const [form, setForm] = useState({ asset_id: "", key_name: "", expiration_days: 30 });
  const [latestSecret, setLatestSecret] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const isAdmin = user?.role === "admin";

  const loadAccessData = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const assetsResponse = await assets.list();
      const assetsData = assetsResponse?.data?.data ?? [];

      setAssetList(assetsData);
      setForm((current) => ({
        ...current,
        asset_id: current.asset_id || assetsData[0]?._id || "",
      }));

      if (!isAdmin) {
        setUserList(user ? [user] : []);
        setKeyList([]);
        return;
      }

      const [usersResponse, keysResponse] = await Promise.all([
        users.list(),
        apiKeys.list(),
      ]);

      setUserList(usersResponse?.data?.data ?? []);
      setKeyList(keysResponse?.data?.data ?? []);
    } catch (fetchError) {
      console.error("Access management error:", fetchError);
      setError(fetchError?.response?.data?.message || "Failed to load access management data");
    } finally {
      setLoading(false);
    }
  }, [isAdmin, user]);

  useEffect(() => {
    loadAccessData();
  }, [loadAccessData]);

  const handleCreateKey = async () => {
    try {
      setSaving(true);
      setError("");
      const response = await apiKeys.create(form);
      setLatestSecret(response?.data?.apiKey ?? null);
      setForm((current) => ({ ...current, key_name: "" }));
      await loadAccessData();
    } catch (saveError) {
      console.error("API key create error:", saveError);
      setError(saveError?.response?.data?.message || "Failed to create API key");
    } finally {
      setSaving(false);
    }
  };

  const handleRotate = async (keyId) => {
    try {
      setError("");
      const response = await apiKeys.rotate(keyId, { expiration_days: 30 });
      setLatestSecret(response?.data ?? null);
      await loadAccessData();
    } catch (rotateError) {
      console.error("API key rotate error:", rotateError);
      setError(rotateError?.response?.data?.message || "Failed to rotate API key");
    }
  };

  const handleRevoke = async (keyId) => {
    try {
      setError("");
      await apiKeys.revoke(keyId);
      await loadAccessData();
    } catch (revokeError) {
      console.error("API key revoke error:", revokeError);
      setError(revokeError?.response?.data?.message || "Failed to revoke API key");
    }
  };

  const summary = useMemo(() => ({
    users: userList.length,
    admins: userList.filter((entry) => entry.role === "admin").length,
    activeKeys: keyList.filter((key) => key.is_active).length,
    expiredKeys: keyList.filter((key) => key.is_expired).length,
  }), [keyList, userList]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading access management...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Identity / integration credentials</div>
          <h1>Users / API Keys</h1>
          <p>Review user access, monitored assets, and ingestion credentials for the hybrid detection pipeline.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Users</span>
          <strong>{summary.users}</strong>
        </div>
        <div className="metric-card">
          <span>Admins</span>
          <strong>{summary.admins}</strong>
        </div>
        <div className="metric-card">
          <span>Active Keys</span>
          <strong>{summary.activeKeys}</strong>
        </div>
        <div className="metric-card">
          <span>Tracked Assets</span>
          <strong>{assetList.length}</strong>
        </div>
      </section>

      {isAdmin ? (
        <div className="card">
          <h3>Generate API Key</h3>
          <div className="form-grid">
            <select value={form.asset_id} onChange={(event) => setForm((current) => ({ ...current, asset_id: event.target.value }))}>
              {assetList.map((asset) => (
                <option key={asset._id} value={asset._id}>
                  {asset.asset_name}
                </option>
              ))}
            </select>
            <input value={form.key_name} placeholder="Key name" onChange={(event) => setForm((current) => ({ ...current, key_name: event.target.value }))} />
            <input
              type="number"
              min="1"
              value={form.expiration_days}
              onChange={(event) => setForm((current) => ({ ...current, expiration_days: Number(event.target.value) }))}
            />
          </div>
          <button className="scan-btn" disabled={saving || !form.asset_id || !form.key_name} onClick={handleCreateKey}>
            {saving ? "Generating..." : "Generate API Key"}
          </button>

          {latestSecret && (
            <div className="generated-secret">
              <strong>{latestSecret.key_name}</strong>
              <div>Token: <span className="mono-text">{latestSecret.token}</span></div>
              <div>Secret: <span className="mono-text">{latestSecret.secret}</span></div>
            </div>
          )}
        </div>
      ) : (
        <div className="card">
          <h3>Credential Access</h3>
          <p>API key management is limited to the admin role. Your account can still review monitored assets and user access below.</p>
        </div>
      )}

      <div className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Users</h3>
            <span>Organization access</span>
          </div>
          <div className="panel-table">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {userList.map((entry) => (
                  <tr key={entry._id || entry.email}>
                    <td>{entry.email}</td>
                    <td>{entry.username || "-"}</td>
                    <td>{entry.role}</td>
                    <td>{entry.createdAt ? new Date(entry.createdAt).toLocaleString() : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="dashboard-panel panel-wide">
          <div className="panel-header">
            <h3>{isAdmin ? "API Keys" : "Monitored Assets"}</h3>
            <span>{isAdmin ? "Agent ingestion credentials" : "Assets available for agent onboarding"}</span>
          </div>
          {isAdmin ? (
            <div className="panel-table">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Asset</th>
                    <th>Status</th>
                    <th>Usage</th>
                    <th>Last Used</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {keyList.map((key) => (
                    <tr key={key._id}>
                      <td>{key.key_name}</td>
                      <td>{key.asset?.asset_name || key.asset?.asset_id || "-"}</td>
                      <td>{key.is_active ? (key.is_expired ? "Expired" : "Active") : "Revoked"}</td>
                      <td>{key.usage_count || 0}</td>
                      <td>{key.last_used_at ? new Date(key.last_used_at).toLocaleString() : "Never"}</td>
                      <td>
                        <div className="table-actions">
                          <button className="ghost-btn" onClick={() => handleRotate(key._id)} disabled={!key.is_active}>
                            Rotate
                          </button>
                          <button className="ghost-btn" onClick={() => handleRevoke(key._id)} disabled={!key.is_active}>
                            Revoke
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="panel-table">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Hostname</th>
                    <th>Agent Status</th>
                    <th>Telemetry</th>
                  </tr>
                </thead>
                <tbody>
                  {assetList.map((asset) => (
                    <tr key={asset._id}>
                      <td>{asset.asset_name}</td>
                      <td>{asset.asset_type}</td>
                      <td>{asset.hostname || "-"}</td>
                      <td>{asset.agent_status || "-"}</td>
                      <td>{Array.isArray(asset.telemetry_types) ? asset.telemetry_types.join(", ") || "-" : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  );
};

export default AccessManagement;
