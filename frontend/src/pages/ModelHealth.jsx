import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, logs } from "../services/api";

const normalizeStatus = (value) => {
  const normalized = String(value || "unknown").toLowerCase();
  return normalized === "ok" ? "online" : normalized;
};

const ModelHealth = () => {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [alertList, setAlertList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchModelHealth = async () => {
      try {
        setLoading(true);
        setError("");
        const [healthResponse, statsResponse, alertsResponse, logsResponse] = await Promise.all([
          dashboard.health(),
          dashboard.stats(),
          alerts.list(120, 1),
          logs.list(120, 1)
        ]);
        setHealth(healthResponse?.data ?? null);
        setStats(statsResponse?.data ?? null);
        setAlertList(alertsResponse?.data?.data ?? []);
        setLogList(logsResponse?.data?.data ?? []);
      } catch (fetchError) {
        console.error("Model health error:", fetchError);
        setError("Failed to load model health");
      } finally {
        setLoading(false);
      }
    };

    fetchModelHealth();
  }, []);

  const derived = useMemo(() => {
    const falsePositives = alertList.filter((alert) => alert.status === "False Positive").length;
    const totalAlerts = alertList.length || 1;
    return {
      falsePositives,
      falsePositiveRate: Math.round((falsePositives / totalAlerts) * 100),
      idsEvents: logList.filter((log) => Boolean(log.metadata?.idsEngine)).length,
      modelStatus: normalizeStatus(health?.idsEngine?.status),
      algorithm: health?.idsEngine?.algorithm || "Unavailable",
      modelLoaded:
        health?.idsEngine?.modelLoaded === null || health?.idsEngine?.modelLoaded === undefined
          ? null
          : Boolean(health?.idsEngine?.modelLoaded),
      usingFallback:
        health?.idsEngine?.usingFallback === null || health?.idsEngine?.usingFallback === undefined
          ? null
          : Boolean(health?.idsEngine?.usingFallback)
    };
  }, [
    alertList,
    logList,
    health?.idsEngine?.algorithm,
    health?.idsEngine?.modelLoaded,
    health?.idsEngine?.status,
    health?.idsEngine?.usingFallback,
  ]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Checking model health...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / IDS availability / model performance</div>
          <h1>Model Health</h1>
          <p>Monitor IDS connectivity, recent anomaly activity, and operational quality signals for the detection stack.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>IDS Engine</span>
          <strong>{derived.modelStatus}</strong>
        </div>
        <div className="metric-card">
          <span>Database</span>
          <strong>{health?.database || "unknown"}</strong>
        </div>
        <div className="metric-card">
          <span>False Positive Rate</span>
          <strong>{derived.falsePositiveRate}%</strong>
        </div>
        <div className="metric-card">
          <span>IDS Events</span>
          <strong>{derived.idsEvents}</strong>
        </div>
        <div className="metric-card">
          <span>Algorithm</span>
          <strong>{derived.algorithm}</strong>
        </div>
      </section>

      <div className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Runtime</h3>
            <span>Current engine state</span>
          </div>
          <div className="panel-list">
            <div className="list-row"><span>Model Artifact</span><strong>attack_model.pkl</strong></div>
            <div className="list-row"><span>Model Loaded</span><strong>{derived.modelLoaded === null ? "Unknown" : derived.modelLoaded ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>Fallback Active</span><strong>{derived.usingFallback === null ? "Unknown" : derived.usingFallback ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>Last Detection</span><strong>{health?.lastDetectionTime ? new Date(health.lastDetectionTime).toLocaleString() : "No detections"}</strong></div>
            <div className="list-row"><span>Total Alerts</span><strong>{stats?.alerts?.total ?? 0}</strong></div>
            <div className="list-row"><span>24h Events</span><strong>{stats?.traffic?.eventsLast24h ?? 0}</strong></div>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Quality Signals</h3>
            <span>Operational confidence</span>
          </div>
          <div className="panel-list">
            <div className="list-row"><span>False Positives</span><strong>{derived.falsePositives}</strong></div>
            <div className="list-row"><span>Critical Alerts</span><strong>{stats?.alerts?.critical ?? 0}</strong></div>
            <div className="list-row"><span>High Alerts</span><strong>{stats?.alerts?.high ?? 0}</strong></div>
            <div className="list-row"><span>Live Snort Events</span><strong>{stats?.traffic?.liveSnortEventsLast24h ?? 0}</strong></div>
            <div className="list-row"><span>ML Anomalies</span><strong>{stats?.traffic?.mlAnomaliesLast24h ?? 0}</strong></div>
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default ModelHealth;
