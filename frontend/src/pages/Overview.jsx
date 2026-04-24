import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";
import { dashboard } from "../services/api";

const formatTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const Overview = () => {
  const [overview, setOverview] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchOverview = async () => {
      try {
        setLoading(true);
        setError("");

        const [overviewResponse, healthResponse] = await Promise.all([
          dashboard.overview(),
          dashboard.health(),
        ]);

        setOverview(overviewResponse?.data?.data ?? {});
        setHealth(healthResponse?.data ?? {});
      } catch (fetchError) {
        console.error("Overview error:", fetchError);
        setError(fetchError?.response?.data?.message || "Failed to load overview.");
      } finally {
        setLoading(false);
      }
    };

    fetchOverview();
  }, []);

  const executive = overview?.executive ?? {};
  const posture = overview?.posture ?? {};
  const operations = overview?.operations?.liveFeed ?? [];
  const detectionStatus = useMemo(
    () => [
      { label: "Monitored Endpoints", value: executive.monitoredEndpoints ?? 0, link: "/assets" },
      { label: "Online Endpoints", value: executive.onlineEndpoints ?? 0, link: "/live-monitoring" },
      { label: "Alerts Last 24h", value: executive.alertsLast24h ?? 0, link: "/alerts" },
      { label: "Open Incidents", value: executive.openIncidents ?? 0, link: "/incidents" },
      { label: "Critical Alerts", value: posture.criticalAlerts ?? 0, link: "/alerts" },
      { label: "Sensor Coverage", value: `${posture.sensorCoveragePercent ?? 0}%`, link: "/model-health" },
    ],
    [executive, posture]
  );

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading overview...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="overview-page">
        <section className="overview-hero">
          <div>
            <div className="command-eyebrow">ThreatLens / Overview / Executive Snapshot</div>
            <h2>Executive Security Posture</h2>
            <p>
              A concise operational view of endpoint coverage, live detections, and stack health for
              daily analyst workflows.
            </p>
          </div>

          <div className="overview-hero__badges">
            <span className="live-badge">Collector {health?.collector?.status || "unknown"}</span>
            <span className="live-badge">Heartbeat {formatTime(health?.collector?.lastHeartbeatAt)}</span>
          </div>
        </section>

        {error && <div className="error-message">{error}</div>}

        <section className="metrics-grid overview-metrics-grid">
          {detectionStatus.map((item) => (
            <Link key={item.label} to={item.link} className="overview-card-link">
              <div className="metric-card metric-card--subtle">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            </Link>
          ))}
        </section>

        <section className="dashboard-grid dashboard-grid--premium overview-grid">
          <div className="dashboard-panel panel-span-2">
            <div className="panel-header">
              <h3>Platform Status</h3>
              <span>Current health across the monitoring stack</span>
            </div>
            <div className="details-grid">
              <div>
                <strong>Database</strong>
                <div>{health?.database || "unknown"}</div>
              </div>
              <div>
                <strong>NIDS</strong>
                <div>{health?.snort?.status || "unknown"}</div>
              </div>
              <div>
                <strong>HIDS</strong>
                <div>{health?.host?.status || "unknown"}</div>
              </div>
              <div>
                <strong>IDS Engine</strong>
                <div>{health?.idsEngine?.status || "unknown"}</div>
              </div>
              <div>
                <strong>Collector</strong>
                <div>{health?.collector?.status || "unknown"}</div>
              </div>
              <div>
                <strong>Last Heartbeat</strong>
                <div>{formatTime(health?.collector?.lastHeartbeatAt)}</div>
              </div>
            </div>
          </div>

          <div className="dashboard-panel">
            <div className="panel-header">
              <h3>Quick Access</h3>
              <span>Common operator workflows</span>
            </div>
            <div className="panel-list">
              <Link className="list-row list-row--pill" to="/upload">
                <span>Upload CSV evidence</span>
                <strong>Open</strong>
              </Link>
              <Link className="list-row list-row--pill" to="/live-monitoring">
                <span>Live Monitoring</span>
                <strong>Watch</strong>
              </Link>
              <Link className="list-row list-row--pill" to="/blocked-ips">
                <span>Blocked IP review</span>
                <strong>Inspect</strong>
              </Link>
            </div>
          </div>

          <div className="dashboard-panel panel-span-3">
            <div className="panel-header">
              <h3>Recent Operations Feed</h3>
              <span>Latest analyst-visible events</span>
            </div>
            <div className="panel-list">
              {(operations.length ? operations : []).slice(0, 6).map((item, index) => (
                <div key={item.id || index} className="list-row list-row-stack">
                  <div className="list-row__top">
                    <strong>{item.title || item.label || "Telemetry Event"}</strong>
                    <span>{formatTime(item.timestamp)}</span>
                  </div>
                  <div className="list-meta">{item.summary || item.meta || item.type || "Activity detected"}</div>
                </div>
              ))}
              {!operations.length && (
                <div className="empty-state">
                  <h3>No live operations yet</h3>
                  <p>Incoming dashboard activity will appear here as telemetry arrives.</p>
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </MainLayout>
  );
};

export default Overview;
