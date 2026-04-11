import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, logs } from "../services/api";

const storageKey = "threatlens-threat-intel";

const ThreatIntel = () => {
  const [alertsList, setAlertsList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [watchlist, setWatchlist] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem(storageKey) || "[]");
    } catch {
      return [];
    }
  });
  const [draftIp, setDraftIp] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    localStorage.setItem(storageKey, JSON.stringify(watchlist));
  }, [watchlist]);

  useEffect(() => {
    const fetchIntel = async () => {
      try {
        setLoading(true);
        setError("");
        const [alertResponse, logResponse] = await Promise.all([alerts.list(120, 1), logs.list(120, 1)]);
        setAlertsList(alertResponse?.data?.data ?? []);
        setLogList(logResponse?.data?.data ?? []);
      } catch (fetchError) {
        console.error("Threat intel error:", fetchError);
        setError("Failed to load threat intelligence data");
      } finally {
        setLoading(false);
      }
    };

    fetchIntel();
  }, []);

  const suspiciousIps = useMemo(() => {
    const scores = new Map();

    alertsList.forEach((alert) => {
      const key = alert.ip || "unknown";
      const current = scores.get(key) || { ip: key, alerts: 0, risk: 0 };
      current.alerts += 1;
      current.risk += Number(alert.risk_score || 0);
      scores.set(key, current);
    });

    return [...scores.values()]
      .map((item) => ({ ...item, avgRisk: Math.round(item.risk / item.alerts) }))
      .sort((left, right) => right.avgRisk - left.avgRisk)
      .slice(0, 10);
  }, [alertsList]);

  const countryRows = useMemo(() => {
    const counts = new Map();

    logList.forEach((log) => {
      const country = log.metadata?.sourceCountry;
      if (!country) return;
      counts.set(country, (counts.get(country) || 0) + 1);
    });

    return [...counts.entries()]
      .map(([country, count]) => ({ country, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 8);
  }, [logList]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading threat intelligence...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Watchlists / suspicious entities</div>
          <h1>Threat Intel</h1>
          <p>Track high-risk IPs, source geographies, and your local analyst watchlist for repeat threat actors.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Watchlist Entries</span>
          <strong>{watchlist.length}</strong>
        </div>
        <div className="metric-card">
          <span>Tracked Suspicious IPs</span>
          <strong>{suspiciousIps.length}</strong>
        </div>
        <div className="metric-card">
          <span>Source Countries</span>
          <strong>{countryRows.length}</strong>
        </div>
        <div className="metric-card">
          <span>Threat Signals</span>
          <strong>{alertsList.length + logList.length}</strong>
        </div>
      </section>

      <div className="card">
        <h3>Local Watchlist</h3>
        <div className="action-row">
          <input value={draftIp} placeholder="Add IP or note" onChange={(event) => setDraftIp(event.target.value)} />
          <button
            className="scan-btn"
            onClick={() => {
              if (!draftIp.trim()) return;
              setWatchlist((current) => [...current, { id: Date.now(), value: draftIp.trim() }]);
              setDraftIp("");
            }}
          >
            Add Watchlist Item
          </button>
        </div>
        <div className="panel-list">
          {watchlist.length > 0 ? (
            watchlist.map((entry) => (
              <div key={entry.id} className="list-row">
                <span className="mono-text">{entry.value}</span>
                <button className="ghost-btn" onClick={() => setWatchlist((current) => current.filter((item) => item.id !== entry.id))}>
                  Remove
                </button>
              </div>
            ))
          ) : (
            <p>No analyst watchlist entries yet.</p>
          )}
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Suspicious IPs</h3>
            <span>Alert-derived risk ranking</span>
          </div>
          <div className="panel-list">
            {suspiciousIps.length > 0 ? (
              suspiciousIps.map((item) => (
                <div key={item.ip} className="list-row">
                  <span className="mono-text">{item.ip}</span>
                  <strong>{item.alerts} alerts / {item.avgRisk} risk</strong>
                </div>
              ))
            ) : (
              <p>No suspicious IPs yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Source Countries</h3>
            <span>Log-derived origin signals</span>
          </div>
          <div className="panel-list">
            {countryRows.length > 0 ? (
              countryRows.map((item) => (
                <div key={item.country} className="list-row">
                  <span>{item.country}</span>
                  <strong>{item.count}</strong>
                </div>
              ))
            ) : (
              <p>No geographic data yet.</p>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default ThreatIntel;
