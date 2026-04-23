import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { assets } from "../services/api";
import { useAuth } from "../context/AuthContext";

const emptyForm = {
  asset_name: "",
  asset_type: "agent",
  asset_criticality: "medium",
  hostname: "",
  ip_address: "",
  host_platform: "windows",
  telemetry_types: ["host"]
};

const Assets = () => {
  const { user } = useAuth();
  const [assetList, setAssetList] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const loadAssets = async () => {
    try {
      setLoading(true);
      setError("");
      const response = await assets.list();
      setAssetList(response?.data?.data ?? []);
    } catch (fetchError) {
      console.error("Assets fetch error:", fetchError);
      setError("Failed to fetch assets");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const handleCreate = async () => {
    try {
      setSaving(true);
      setError("");
      if (form.asset_type === "agent") {
        await assets.create(form);
      } else {
        await assets.create(form);
      }
      setForm(emptyForm);
      await loadAssets();
    } catch (saveError) {
      console.error("Asset create error:", saveError);
      setError(saveError?.response?.data?.message || "Failed to create asset");
    } finally {
      setSaving(false);
    }
  };

  const overview = useMemo(() => {
    return assetList.reduce(
      (accumulator, asset) => {
        accumulator.total += 1;
        if (asset.agent_status === "online") accumulator.online += 1;
        if (asset.asset_criticality === "critical") accumulator.critical += 1;
        if ((asset.asset_status || asset.status) === "active") accumulator.active += 1;
        return accumulator;
      },
      { total: 0, online: 0, critical: 0, active: 0 }
    );
  }, [assetList]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading assets...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Asset inventory / monitored estate</div>
          <h1>Assets</h1>
          <p>Track monitored infrastructure, criticality, agent status, and host coverage across your organization.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Total Assets</span>
          <strong>{overview.total}</strong>
        </div>
        <div className="metric-card">
          <span>Active</span>
          <strong>{overview.active}</strong>
        </div>
        <div className="metric-card">
          <span>Agent Online</span>
          <strong>{overview.online}</strong>
        </div>
        <div className="metric-card">
          <span>Critical Assets</span>
          <strong>{overview.critical}</strong>
        </div>
      </section>

      {user?.role === "admin" && (
        <div className="card">
          <h3>Register Asset</h3>
          <div className="form-grid">
            <input
              value={form.asset_name}
              placeholder="Asset name"
              onChange={(event) => setForm((previous) => ({ ...previous, asset_name: event.target.value }))}
            />
            <select
              value={form.asset_type}
              onChange={(event) => setForm((previous) => ({ ...previous, asset_type: event.target.value }))}
            >
              <option value="agent">Agent</option>
              <option value="web_server">Web Server</option>
              <option value="api_server">API Server</option>
              <option value="database">Database</option>
              <option value="firewall">Firewall</option>
              <option value="other">Other</option>
            </select>
            <select
              value={form.asset_criticality}
              onChange={(event) => setForm((previous) => ({ ...previous, asset_criticality: event.target.value }))}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
            <input
              value={form.hostname}
              placeholder="Hostname"
              onChange={(event) => setForm((previous) => ({ ...previous, hostname: event.target.value }))}
            />
            <input
              value={form.ip_address}
              placeholder="IP address"
              onChange={(event) => setForm((previous) => ({ ...previous, ip_address: event.target.value }))}
            />
            <select
              value={form.host_platform}
              onChange={(event) => setForm((previous) => ({ ...previous, host_platform: event.target.value }))}
            >
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
            </select>
          </div>
          <button className="scan-btn" disabled={saving || !form.asset_name} onClick={handleCreate}>
            {saving ? "Creating asset..." : "Create Asset"}
          </button>
        </div>
      )}

      <div className="card">
        {assetList.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Criticality</th>
                <th>Hostname</th>
                <th>IP</th>
                <th>Asset Status</th>
                <th>Agent Status</th>
                <th>Platform</th>
                <th>Telemetry</th>
                <th>Last Activity</th>
              </tr>
            </thead>
            <tbody>
              {assetList.map((asset) => (
                <tr key={asset._id}>
                  <td>{asset.asset_name}</td>
                  <td>{asset.asset_type}</td>
                  <td>{asset.asset_criticality}</td>
                  <td>{asset.hostname || "-"}</td>
                  <td className="mono-text">{asset.ip_address || "-"}</td>
                  <td>{asset.asset_status || asset.status || "-"}</td>
                  <td>{asset.agent_status}</td>
                  <td>{asset.host_platform || "-"}</td>
                  <td>{Array.isArray(asset.telemetry_types) ? asset.telemetry_types.join(", ") || "-" : "-"}</td>
                  <td>{asset.last_activity ? new Date(asset.last_activity).toLocaleString() : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No assets registered yet.</p>
        )}
      </div>
    </MainLayout>
  );
};

export default Assets;
