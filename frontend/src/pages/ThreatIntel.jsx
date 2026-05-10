import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { intel } from "../services/api";
import { useAuth } from "../context/AuthContext";

const ThreatIntel = () => {
  const { user } = useAuth();

  const [summary, setSummary] = useState(null);
  const [watchlist, setWatchlist] = useState([]);
  const [draftIp, setDraftIp] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const isAdmin = user?.role === "admin";

  const fetchIntel = async () => {
    try {
      setLoading(true);
      setError("");

      const [summaryResponse, watchlistResponse] = await Promise.all([
        intel.threatIntel(),
        intel.watchlist(),
      ]);

      setSummary(summaryResponse?.data?.data ?? null);
      setWatchlist(watchlistResponse?.data?.data ?? []);
    } catch (err) {
      console.error("Threat intel error:", err);
      setError("Failed to load threat intelligence data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntel();
  }, []);

  const metrics = useMemo(() => {
    const totals = summary?.totals || {};

    return {
      watchlistEntries: watchlist.length,
      suspiciousIps: summary?.suspiciousIps?.length || 0,
      sourceCountries: summary?.sourceCountries?.length || 0,
      threatSignals: Number(totals.alerts || 0) + Number(totals.logs || 0),
    };
  }, [summary, watchlist]);

  const handleCreateIndicator = async () => {
    if (!draftIp.trim()) return;

    try {
      setSaving(true);
      setError("");

      await intel.createIndicator({
        indicator_type: "ip",
        value: draftIp.trim(),
      });

      setDraftIp("");

      const [summaryResponse, watchlistResponse] = await Promise.all([
        intel.threatIntel(),
        intel.watchlist(),
      ]);

      setSummary(summaryResponse?.data?.data ?? null);
      setWatchlist(watchlistResponse?.data?.data ?? []);
    } catch (err) {
      console.error("Create indicator error:", err);
      setError("Failed to create watchlist indicator");
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteIndicator = async (id) => {
    try {
      setError("");
      await intel.deleteIndicator(id);
      setWatchlist((current) => current.filter((item) => item._id !== id));
    } catch (err) {
      console.error("Delete indicator error:", err);
      setError("Failed to delete watchlist indicator");
    }
  };

  const getRiskLabel = (risk) => {
    const value = Number(risk || 0);
    if (value >= 80) return "critical";
    if (value >= 60) return "high";
    if (value >= 35) return "medium";
    return "low";
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="tl-loading">Collating threat intelligence...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header tl-page-header">
        <div>
          <div className="command-eyebrow">
            THREATLENS / INTELLIGENCE / WATCHLIST
          </div>
          <h1>Threat Intelligence</h1>
          <p>
            Track suspicious IPs, attack families, geographic origins, and
            manually managed indicators from live ThreatLens telemetry.
          </p>
        </div>

        <button className="tl-refresh-btn" onClick={fetchIntel}>
          Refresh Intel
        </button>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="tl-metric-grid">
        <div className="tl-metric-card">
          <span>Watchlist Entries</span>
          <strong>{metrics.watchlistEntries}</strong>
          <small>Tracked indicators</small>
        </div>

        <div className="tl-metric-card">
          <span>Suspicious IPs</span>
          <strong>{metrics.suspiciousIps}</strong>
          <small>High-risk senders</small>
        </div>

        <div className="tl-metric-card">
          <span>Source Countries</span>
          <strong>{metrics.sourceCountries}</strong>
          <small>Threat origins</small>
        </div>

        <div className="tl-metric-card">
          <span>Total Signals</span>
          <strong>{metrics.threatSignals}</strong>
          <small>Logs + alerts analyzed</small>
        </div>
      </section>

      <section className="tl-orange-panel">
        <div className="tl-orange-panel-header">
          <h2>▦ Strategic Watchlist</h2>
          <span>{watchlist.length} indicators tracked</span>
        </div>

        <div className="tl-panel-body">
          <div className="tl-watchlist-form">
            <input
              value={draftIp}
              placeholder="Enter IP address, e.g. 192.168.1.10"
              onChange={(e) => setDraftIp(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && isAdmin) handleCreateIndicator();
              }}
            />

            <button
              className="tl-primary-btn"
              disabled={!isAdmin || !draftIp.trim() || saving}
              onClick={handleCreateIndicator}
            >
              {saving ? "Adding..." : isAdmin ? "Add Indicator" : "Admin Only"}
            </button>
          </div>

          <div className="tl-table-wrap">
            <table className="tl-data-table">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Access</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {watchlist.map((entry) => (
                  <tr key={entry._id}>
                    <td className="mono">{entry.value}</td>
                    <td>
                      <span className="tl-pill blue">
                        {entry.indicator_type || "IP"}
                      </span>
                    </td>
                    <td>
                      <span className="tl-pill green">ACTIVE</span>
                    </td>
                    <td>{isAdmin ? "Admin managed" : "Read only"}</td>
                    <td>
                      {isAdmin ? (
                        <button
                          className="tl-danger-btn"
                          onClick={() => handleDeleteIndicator(entry._id)}
                        >
                          Remove
                        </button>
                      ) : (
                        <span className="tl-muted">Restricted</span>
                      )}
                    </td>
                  </tr>
                ))}

                {!watchlist.length && (
                  <tr>
                    <td colSpan="5" className="tl-empty">
                      No watchlist indicators added yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="tl-intel-grid">
        <div className="tl-orange-panel">
          <div className="tl-orange-panel-header">
            <h2>▦ Top Suspicious IPs</h2>
            <span>{summary?.suspiciousIps?.length || 0} found</span>
          </div>

          <div className="tl-panel-body">
            <div className="tl-table-wrap">
              <table className="tl-data-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Attack Types</th>
                    <th>Risk</th>
                  </tr>
                </thead>

                <tbody>
                  {summary?.suspiciousIps?.map((item) => (
                    <tr key={item.ip}>
                      <td className="mono">{item.ip}</td>
                      <td>
                        {item.attackTypes?.length
                          ? item.attackTypes.join(", ")
                          : "Suspicious activity"}
                      </td>
                      <td>
                        <span className={`tl-pill ${getRiskLabel(item.avgRisk)}`}>
                          {item.avgRisk || 0}%
                        </span>
                      </td>
                    </tr>
                  ))}

                  {!summary?.suspiciousIps?.length && (
                    <tr>
                      <td colSpan="3" className="tl-empty">
                        No suspicious IPs detected.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="tl-orange-panel">
          <div className="tl-orange-panel-header">
            <h2>▦ Geographic Origins</h2>
            <span>{summary?.sourceCountries?.length || 0} countries</span>
          </div>

          <div className="tl-panel-body">
            <div className="tl-table-wrap">
              <table className="tl-data-table">
                <thead>
                  <tr>
                    <th>Country</th>
                    <th>Signals</th>
                  </tr>
                </thead>

                <tbody>
                  {summary?.sourceCountries?.map((item) => (
                    <tr key={item.country}>
                      <td>{item.country || "Unknown"}</td>
                      <td>
                        <span className="tl-pill blue">{item.count}</span>
                      </td>
                    </tr>
                  ))}

                  {!summary?.sourceCountries?.length && (
                    <tr>
                      <td colSpan="2" className="tl-empty">
                        No geographic intelligence available.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="tl-orange-panel">
          <div className="tl-orange-panel-header">
            <h2>▦ Threat Families</h2>
            <span>{summary?.topFamilies?.length || 0} categories</span>
          </div>

          <div className="tl-panel-body">
            <div className="tl-table-wrap">
              <table className="tl-data-table">
                <thead>
                  <tr>
                    <th>Threat Family</th>
                    <th>Count</th>
                  </tr>
                </thead>

                <tbody>
                  {summary?.topFamilies?.map((item) => (
                    <tr key={item.name}>
                      <td>{item.name || "Unknown Threat"}</td>
                      <td>
                        <span className="tl-pill orange">{item.value}</span>
                      </td>
                    </tr>
                  ))}

                  {!summary?.topFamilies?.length && (
                    <tr>
                      <td colSpan="2" className="tl-empty">
                        No threat family data available.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>
    </MainLayout>
  );
};

export default ThreatIntel;