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
  telemetry_types: ["host"],
};

const formatDate = (value) => {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
};

const getStatusClass = (status = "") => {
  const value = String(status).toLowerCase();
  if (value === "online" || value === "active") return "status-online";
  if (value === "offline" || value === "inactive") return "status-offline";
  return "status-unknown";
};

const getCriticalityClass = (criticality = "") => {
  const value = String(criticality).toLowerCase();
  if (value === "critical") return "criticality-critical";
  if (value === "high") return "criticality-high";
  if (value === "medium") return "criticality-medium";
  return "criticality-low";
};

const Assets = () => {
  const { user } = useAuth();

  const [assetList, setAssetList] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const isAdmin = user?.role === "admin";

  const loadAssets = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await assets.list();
      setAssetList(response?.data?.data ?? []);
    } catch (fetchError) {
      setError(fetchError?.response?.data?.message || "Failed to fetch assets.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const validateAsset = () => {
    if (!form.asset_name.trim()) return "Asset name is required.";
    if (!form.hostname.trim()) return "Hostname is required.";
    if (!form.ip_address.trim()) return "IP address is required.";
    return "";
  };

  const handleCreate = async () => {
    const validationError = validateAsset();

    if (validationError) {
      setError(validationError);
      setFeedback("");
      return;
    }

    try {
      setSaving(true);
      setError("");
      setFeedback("");

      await assets.create({
        ...form,
        asset_name: form.asset_name.trim(),
        hostname: form.hostname.trim(),
        ip_address: form.ip_address.trim(),
      });

      setForm(emptyForm);
      setFeedback("Asset registered successfully.");
      await loadAssets();
    } catch (saveError) {
      setError(saveError?.response?.data?.message || "Failed to create asset.");
    } finally {
      setSaving(false);
    }
  };

  const overview = useMemo(() => {
    return assetList.reduce(
      (acc, asset) => {
        const assetStatus = String(asset.asset_status || asset.status || "").toLowerCase();
        const agentStatus = String(asset.agent_status || "").toLowerCase();
        const criticality = String(asset.asset_criticality || "").toLowerCase();

        acc.total += 1;
        if (assetStatus === "active") acc.active += 1;
        if (agentStatus === "online") acc.online += 1;
        if (criticality === "critical") acc.critical += 1;
        if (asset.host_platform === "linux") acc.linux += 1;

        return acc;
      },
      { total: 0, online: 0, critical: 0, active: 0, linux: 0 }
    );
  }, [assetList]);

  const filteredAssets = useMemo(() => {
    return assetList.filter((asset) => {
      const keyword = search.toLowerCase();
      const assetStatus = String(asset.asset_status || asset.status || "").toLowerCase();

      const matchesSearch =
        !keyword ||
        asset.asset_name?.toLowerCase().includes(keyword) ||
        asset.hostname?.toLowerCase().includes(keyword) ||
        asset.ip_address?.toLowerCase().includes(keyword) ||
        asset.asset_type?.toLowerCase().includes(keyword);

      const matchesType = !typeFilter || asset.asset_type === typeFilter;
      const matchesStatus = !statusFilter || assetStatus === statusFilter;

      return matchesSearch && matchesType && matchesStatus;
    });
  }, [assetList, search, typeFilter, statusFilter]);

  const updateTelemetryType = (type, checked) => {
    setForm((current) => {
      const currentTypes = Array.isArray(current.telemetry_types)
        ? current.telemetry_types
        : [];

      return {
        ...current,
        telemetry_types: checked
          ? [...new Set([...currentTypes, type])]
          : currentTypes.filter((item) => item !== type),
      };
    });
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading assets...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <style>{`
        .assets-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background: linear-gradient(135deg, #fff7ed 0%, #f8fbff 55%, #eef9f1 100%);
        }

        .assets-shell {
          max-width: 1240px;
          margin: 0 auto;
        }

        .assets-header {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 24px;
          padding: 30px;
          margin-bottom: 24px;
          box-shadow: 0 18px 45px rgba(15,23,42,.08);
        }

        .assets-eyebrow {
          color: #0ea5e9;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: .12em;
          margin-bottom: 8px;
        }

        .assets-header h1 {
          margin: 0;
          font-size: 34px;
          color: #0f2742;
        }

        .assets-header p {
          margin: 10px 0 0;
          color: #64748b;
          line-height: 1.6;
        }

        .assets-metrics {
          display: grid;
          grid-template-columns: repeat(5, minmax(0, 1fr));
          gap: 18px;
          margin-bottom: 22px;
        }

        .asset-metric-card,
        .assets-card {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          box-shadow: 0 14px 34px rgba(15,23,42,.07);
        }

        .asset-metric-card {
          border-radius: 20px;
          padding: 22px;
        }

        .asset-metric-card span {
          display: block;
          font-size: 12px;
          color: #64748b;
          font-weight: 900;
          text-transform: uppercase;
          margin-bottom: 10px;
        }

        .asset-metric-card strong {
          font-size: 30px;
          color: #0f2742;
        }

        .assets-card {
          border-radius: 24px;
          padding: 24px;
          margin-bottom: 22px;
        }

        .assets-card h3 {
          margin: 0 0 6px;
          color: #172033;
          font-size: 21px;
        }

        .assets-card p {
          margin: 0 0 20px;
          color: #64748b;
          line-height: 1.6;
        }

        .assets-form-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 16px;
          margin-bottom: 18px;
        }

        .asset-field {
          display: grid;
          gap: 9px;
        }

        .asset-field label {
          font-size: 13px;
          font-weight: 900;
          color: #334155;
        }

        .asset-field input,
        .asset-field select,
        .assets-filter-bar input,
        .assets-filter-bar select {
          width: 100%;
          border: 1px solid #dbe3ef;
          background: #f8fbff;
          border-radius: 14px;
          padding: 13px 14px;
          outline: none;
          color: #172033;
          font-size: 14px;
        }

        .asset-field input:focus,
        .asset-field select:focus,
        .assets-filter-bar input:focus,
        .assets-filter-bar select:focus {
          border-color: #0ea5e9;
          box-shadow: 0 0 0 4px rgba(14,165,233,.12);
          background: #fff;
        }

        .telemetry-box {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          margin: 4px 0 18px;
        }

        .telemetry-chip {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 10px 14px;
          border-radius: 999px;
          background: #f8fbff;
          border: 1px solid #dbe3ef;
          color: #334155;
          font-weight: 800;
          font-size: 13px;
        }

        .telemetry-chip input {
          accent-color: #0ea5e9;
        }

        .primary-btn,
        .secondary-btn {
          border: 0;
          border-radius: 14px;
          padding: 12px 17px;
          font-weight: 900;
          cursor: pointer;
          transition: .2s ease;
        }

        .primary-btn {
          color: #fff;
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
          box-shadow: 0 12px 26px rgba(37,99,235,.22);
        }

        .secondary-btn {
          background: #eef6ff;
          color: #0f2742;
          border: 1px solid #dbeafe;
        }

        .primary-btn:disabled,
        .secondary-btn:disabled {
          opacity: .55;
          cursor: not-allowed;
        }

        .assets-actions {
          display: flex;
          justify-content: flex-end;
        }

        .assets-filter-bar {
          display: grid;
          grid-template-columns: 2fr 1fr 1fr;
          gap: 14px;
          margin-bottom: 18px;
        }

        .assets-table-wrapper {
          overflow-x: auto;
        }

        .assets-table {
          width: 100%;
          border-collapse: collapse;
          min-width: 1050px;
        }

        .assets-table th,
        .assets-table td {
          text-align: left;
          padding: 16px 18px;
          border-bottom: 1px solid #eef2f7;
          vertical-align: top;
        }

        .assets-table th {
          background: #f8fbff;
          color: #475569;
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: .08em;
        }

        .assets-table td {
          color: #172033;
          font-size: 14px;
        }

        .asset-name {
          font-weight: 900;
          color: #0f2742;
        }

        .mono-text {
          font-family: Consolas, monospace;
          font-weight: 800;
        }

        .status-pill,
        .criticality-pill {
          display: inline-flex;
          padding: 6px 10px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 900;
          white-space: nowrap;
        }

        .status-online {
          background: #ecfdf5;
          color: #047857;
        }

        .status-offline {
          background: #fff1f2;
          color: #be123c;
        }

        .status-unknown {
          background: #f1f5f9;
          color: #64748b;
        }

        .criticality-critical {
          background: #fee2e2;
          color: #991b1b;
        }

        .criticality-high {
          background: #ffedd5;
          color: #9a3412;
        }

        .criticality-medium {
          background: #fef9c3;
          color: #854d0e;
        }

        .criticality-low {
          background: #dcfce7;
          color: #166534;
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

        .empty-assets {
          text-align: center;
          padding: 44px 18px;
          color: #64748b;
        }

        @media (max-width: 1050px) {
          .assets-metrics {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .assets-form-grid,
          .assets-filter-bar {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 700px) {
          .assets-page {
            padding: 16px;
          }

          .assets-header {
            padding: 24px;
          }

          .assets-header h1 {
            font-size: 28px;
          }

          .assets-metrics {
            grid-template-columns: 1fr;
          }

          .assets-actions,
          .primary-btn,
          .secondary-btn {
            width: 100%;
          }
        }
      `}</style>

      <div className="assets-page">
        <div className="assets-shell">
          <section className="assets-header">
            <div className="assets-eyebrow">
              ThreatLens / Asset Inventory / Monitored Estate
            </div>
            <h1>Assets</h1>
            <p>
              Track monitored machines, servers, agents, host platforms, IP addresses,
              telemetry coverage, and collector health across your ThreatLens system.
            </p>
          </section>

          {error && <div className="error-message">{error}</div>}
          {feedback && <div className="success-message">{feedback}</div>}

          <section className="assets-metrics">
            <div className="asset-metric-card">
              <span>Total Assets</span>
              <strong>{overview.total}</strong>
            </div>

            <div className="asset-metric-card">
              <span>Active</span>
              <strong>{overview.active}</strong>
            </div>

            <div className="asset-metric-card">
              <span>Agent Online</span>
              <strong>{overview.online}</strong>
            </div>

            <div className="asset-metric-card">
              <span>Critical</span>
              <strong>{overview.critical}</strong>
            </div>

            <div className="asset-metric-card">
              <span>Linux Hosts</span>
              <strong>{overview.linux}</strong>
            </div>
          </section>

          {isAdmin && (
            <section className="assets-card">
              <h3>Register Asset</h3>
              <p>
                Register endpoints, servers, network sensors, or monitored hosts before
                connecting HIDS/NIDS agents.
              </p>

              <div className="assets-form-grid">
                <div className="asset-field">
                  <label>Asset Name</label>
                  <input
                    value={form.asset_name}
                    placeholder="e.g. Finance Workstation"
                    onChange={(event) =>
                      setForm((previous) => ({
                        ...previous,
                        asset_name: event.target.value,
                      }))
                    }
                  />
                </div>

                <div className="asset-field">
                  <label>Asset Type</label>
                  <select
                    value={form.asset_type}
                    onChange={(event) =>
                      setForm((previous) => ({
                        ...previous,
                        asset_type: event.target.value,
                      }))
                    }
                  >
                    <option value="agent">Agent</option>
                    <option value="web_server">Web Server</option>
                    <option value="api_server">API Server</option>
                    <option value="database">Database</option>
                    <option value="firewall">Firewall</option>
                    <option value="network_sensor">Network Sensor</option>
                    <option value="workstation">Workstation</option>
                    <option value="other">Other</option>
                  </select>
                </div>

                <div className="asset-field">
                  <label>Criticality</label>
                  <select
                    value={form.asset_criticality}
                    onChange={(event) =>
                      setForm((previous) => ({
                        ...previous,
                        asset_criticality: event.target.value,
                      }))
                    }
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>

                <div className="asset-field">
                  <label>Hostname</label>
                  <input
                    value={form.hostname}
                    placeholder="e.g. host-finance-01"
                    onChange={(event) =>
                      setForm((previous) => ({
                        ...previous,
                        hostname: event.target.value,
                      }))
                    }
                  />
                </div>

                <div className="asset-field">
                  <label>IP Address</label>
                  <input
                    value={form.ip_address}
                    placeholder="e.g. 192.168.1.20"
                    onChange={(event) =>
                      setForm((previous) => ({
                        ...previous,
                        ip_address: event.target.value,
                      }))
                    }
                  />
                </div>

                <div className="asset-field">
                  <label>Host Platform</label>
                  <select
                    value={form.host_platform}
                    onChange={(event) =>
                      setForm((previous) => ({
                        ...previous,
                        host_platform: event.target.value,
                      }))
                    }
                  >
                    <option value="windows">Windows</option>
                    <option value="linux">Linux / Ubuntu</option>
                    <option value="macos">macOS</option>
                    <option value="network">Network Device</option>
                  </select>
                </div>
              </div>

              <label className="asset-field">
                <span>Telemetry Types</span>
              </label>

              <div className="telemetry-box">
                {["host", "network", "auth", "file", "process"].map((type) => (
                  <label className="telemetry-chip" key={type}>
                    <input
                      type="checkbox"
                      checked={form.telemetry_types.includes(type)}
                      onChange={(event) =>
                        updateTelemetryType(type, event.target.checked)
                      }
                    />
                    {type.toUpperCase()}
                  </label>
                ))}
              </div>

              <div className="assets-actions">
                <button
                  type="button"
                  className="primary-btn"
                  disabled={saving || !form.asset_name.trim()}
                  onClick={handleCreate}
                >
                  {saving ? "Creating asset..." : "Create Asset"}
                </button>
              </div>
            </section>
          )}

          <section className="assets-card">
            <h3>Registered Assets</h3>
            <p>
              View all registered assets and confirm which endpoints are actively
              sending telemetry to ThreatLens.
            </p>

            <div className="assets-filter-bar">
              <input
                value={search}
                placeholder="Search by name, hostname, IP, type..."
                onChange={(event) => setSearch(event.target.value)}
              />

              <select
                value={typeFilter}
                onChange={(event) => setTypeFilter(event.target.value)}
              >
                <option value="">All types</option>
                <option value="agent">Agent</option>
                <option value="web_server">Web Server</option>
                <option value="api_server">API Server</option>
                <option value="database">Database</option>
                <option value="firewall">Firewall</option>
                <option value="network_sensor">Network Sensor</option>
                <option value="workstation">Workstation</option>
                <option value="other">Other</option>
              </select>

              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
              >
                <option value="">All statuses</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>
            </div>

            {filteredAssets.length > 0 ? (
              <div className="assets-table-wrapper">
                <table className="assets-table">
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
                    {filteredAssets.map((asset) => {
                      const assetStatus = asset.asset_status || asset.status || "unknown";
                      const agentStatus = asset.agent_status || "unknown";

                      return (
                        <tr key={asset._id}>
                          <td className="asset-name">{asset.asset_name}</td>
                          <td>{asset.asset_type || "-"}</td>
                          <td>
                            <span
                              className={`criticality-pill ${getCriticalityClass(
                                asset.asset_criticality
                              )}`}
                            >
                              {asset.asset_criticality || "-"}
                            </span>
                          </td>
                          <td>{asset.hostname || "-"}</td>
                          <td className="mono-text">{asset.ip_address || "-"}</td>
                          <td>
                            <span className={`status-pill ${getStatusClass(assetStatus)}`}>
                              {assetStatus}
                            </span>
                          </td>
                          <td>
                            <span className={`status-pill ${getStatusClass(agentStatus)}`}>
                              {agentStatus}
                            </span>
                          </td>
                          <td>{asset.host_platform || "-"}</td>
                          <td>
                            {Array.isArray(asset.telemetry_types)
                              ? asset.telemetry_types.join(", ") || "-"
                              : "-"}
                          </td>
                          <td>{formatDate(asset.last_activity)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-assets">
                No assets found. Register an asset or adjust your filters.
              </div>
            )}
          </section>
        </div>
      </div>
    </MainLayout>
  );
};

export default Assets;