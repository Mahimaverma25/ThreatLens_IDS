import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { apiKeys, assets, users } from "../services/api";

const AccessManagement = () => {
  const [userList, setUserList] = useState([]);
  const [keyList, setKeyList] = useState([]);
  const [assetList, setAssetList] = useState([]);
  const [form, setForm] = useState({ asset_id: "", key_name: "", expiration_days: 30 });
  const [latestSecret, setLatestSecret] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const loadAccessData = async () => {
    try {
      setLoading(true);
      setError("");
      const [usersResponse, keysResponse, assetsResponse] = await Promise.all([
        users.list(),
        apiKeys.list(),
        assets.list()
      ]);
      const assetsData = assetsResponse?.data?.data ?? [];
      setUserList(usersResponse?.data?.data ?? []);
      setKeyList(keysResponse?.data?.data ?? []);
      setAssetList(assetsData);
      setForm((current) => ({
        ...current,
        asset_id: current.asset_id || assetsData[0]?._id || ""
      }));
    } catch (fetchError) {
      console.error("Access management error:", fetchError);
      setError(fetchError?.response?.data?.message || "Failed to load access management data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAccessData();
  }, []);

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

  const summary = useMemo(() => {
    return {
      users: userList.length,
      admins: userList.filter((user) => user.role === "admin").length,
      activeKeys: keyList.filter((key) => key.is_active).length,
      expiredKeys: keyList.filter((key) => key.is_expired).length
    };
  }, [userList, keyList]);

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
          <p>Review user access, provision ingestion credentials, and manage monitored asset integrations.</p>
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
          <span>Expired Keys</span>
          <strong>{summary.expiredKeys}</strong>
        </div>
      </section>

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
                {userList.map((user) => (
                  <tr key={user._id}>
                    <td>{user.email}</td>
                    <td>{user.username || "-"}</td>
                    <td>{user.role}</td>
                    <td>{user.createdAt ? new Date(user.createdAt).toLocaleString() : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="dashboard-panel panel-wide">
          <div className="panel-header">
            <h3>API Keys</h3>
            <span>Agent ingestion credentials</span>
          </div>
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
                        <button
                          className="ghost-btn"
                          onClick={async () => {
                            const response = await apiKeys.rotate(key._id, { expiration_days: 30 });
                            setLatestSecret(response?.data ?? null);
                            await loadAccessData();
                          }}
                          disabled={!key.is_active}
                        >
                          Rotate
                        </button>
                        <button
                          className="ghost-btn"
                          onClick={async () => {
                            await apiKeys.revoke(key._id);
                            await loadAccessData();
                          }}
                          disabled={!key.is_active}
                        >
                          Revoke
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default AccessManagement;
