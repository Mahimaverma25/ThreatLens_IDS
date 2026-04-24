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
  const [error, setError] = useState("");
  const isAdmin = user?.role === "admin";

  useEffect(() => {
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
      } catch (fetchError) {
        console.error("Threat intel error:", fetchError);
        setError("Failed to load threat intelligence data");
      } finally {
        setLoading(false);
      }
    };
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
      setError("");
      await intel.createIndicator({ indicator_type: "ip", value: draftIp.trim() });
      setDraftIp("");
      const [summaryResponse, watchlistResponse] = await Promise.all([
        intel.threatIntel(),
        intel.watchlist(),
      ]);
      setSummary(summaryResponse?.data?.data ?? null);
      setWatchlist(watchlistResponse?.data?.data ?? []);
    } catch (createError) {
      console.error("Create indicator error:", createError);
      setError("Failed to create watchlist indicator");
    }
  };

  const handleDeleteIndicator = async (id) => {
    try {
      setError("");
      await intel.deleteIndicator(id);
      setWatchlist((current) => current.filter((item) => item._id !== id));
    } catch (deleteError) {
      console.error("Delete indicator error:", deleteError);
      setError("Failed to delete watchlist indicator");
    }
  };

  if (loading) return <MainLayout><div className="loading">Collating global intelligence...</div></MainLayout>;

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Global Intelligence / Watchlists</div>
          <h1>Threat Intelligence</h1>
          <p>Analyze high-risk entities and geographic threat distributions derived from live platform telemetry.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="hero-metric-grid" style={{ marginBottom: '24px' }}>
        <div className="hero-metric-card"><span>Watchlist Entries</span><strong>{metrics.watchlistEntries}</strong><small>Analyst-tracked IPs</small></div>
        <div className="hero-metric-card"><span>Suspicious IPs</span><strong>{metrics.suspiciousIps}</strong><small>High-risk senders</small></div>
        <div className="hero-metric-card"><span>Source Countries</span><strong>{metrics.sourceCountries}</strong><small>Global threat origins</small></div>
        <div className="hero-metric-card"><span>Total Signals</span><strong>{metrics.threatSignals}</strong><small>Aggregated indicators</small></div>
      </section>

      <div className="card glass animate-in" style={{ marginBottom: '24px' }}>
        <h3>Strategic Watchlist</h3>
        <div className="flex-between" style={{ gap: '16px', marginBottom: '20px' }}>
          <input value={draftIp} placeholder="Enter IP address (e.g. 1.2.3.4)" onChange={e => setDraftIp(e.target.value)} style={{ flex: 1 }}/>
          <button className="btn-primary" disabled={!isAdmin || !draftIp.trim()} onClick={handleCreateIndicator}>
            {isAdmin ? "Add Indicator" : "Admin Only"}
          </button>
        </div>
        <div className="panel-list" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
          {watchlist.map((entry) => (
            <div key={entry._id} className="list-row list-row--pill" style={{ background: 'rgba(255,255,255,0.03)' }}>
              <strong className="mono" style={{ color: 'var(--primary)' }}>{entry.value}</strong>
              {isAdmin && <button className="btn-ghost" onClick={() => handleDeleteIndicator(entry._id)} style={{ padding: '4px' }}>✕</button>}
            </div>
          ))}
          {!watchlist.length && <div style={{ color: 'var(--text-dark)' }}>No indicators tracked.</div>}
        </div>
      </div>

      <div className="dashboard-grid dashboard-grid--premium">
        <div className="dashboard-panel glass animate-in">
          <div className="panel-header"><h3>Top Suspicious IPs</h3><span>Ranked by risk score</span></div>
          <div className="panel-list">
            {summary?.suspiciousIps?.map((item) => (
              <div key={item.ip} className="list-row list-row--pill" style={{ marginBottom: '10px' }}>
                <div style={{ flex: 1 }}>
                  <div className="mono" style={{ fontWeight: '600' }}>{item.ip}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>{item.attackTypes?.join(", ")}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ color: 'var(--primary)', fontWeight: '700' }}>{item.avgRisk}%</div>
                  <div style={{ fontSize: '0.7rem' }}>Risk Score</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-panel glass animate-in">
          <div className="panel-header"><h3>Geographic Origins</h3><span>Top source countries</span></div>
          <div className="panel-list">
            {summary?.sourceCountries?.map((item) => (
              <div key={item.country} className="list-row list-row--pill" style={{ marginBottom: '10px' }}>
                <span>{item.country}</span>
                <strong style={{ color: 'var(--secondary)' }}>{item.count}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-panel glass animate-in">
          <div className="panel-header"><h3>Threat Families</h3><span>Concentration of attack types</span></div>
          <div className="panel-list">
            {summary?.topFamilies?.map((item) => (
              <div key={item.name} className="list-row list-row--pill" style={{ marginBottom: '10px' }}>
                <span>{item.name}</span>
                <strong style={{ color: 'var(--accent)' }}>{item.value}</strong>
              </div>
            ))}
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default ThreatIntel;