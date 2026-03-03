import { useCallback, useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, logs } from "../services/api";
import useSocket from "../hooks/useSocket";

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalAlerts: 0,
    criticalSeverity: 0,
    highSeverity: 0,
    mediumSeverity: 0,
    recentLogs: [],
    health: {
      database: "unknown",
      idsEngine: "unknown",
      lastDetectionTime: null,
    },
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const token = localStorage.getItem("accessToken");

  const fetchStats = useCallback(async () => {
    try {
      const [alertsRes, logsRes, statsRes, healthRes] = await Promise.all([
        alerts.list(100),
        logs.list(10),
        dashboard.stats(),
        dashboard.health(),
      ]);

      const alertsData = alertsRes.data.data || [];
      const logData = logsRes.data.data || [];

      const highSeverity = alertsData.filter((a) => a.severity === "High").length;
      const mediumSeverity = alertsData.filter((a) => a.severity === "Medium").length;
      const criticalSeverity = alertsData.filter((a) => a.severity === "Critical").length;

      setStats({
        totalAlerts: statsRes.data.alerts.total || alertsData.length,
        criticalSeverity: statsRes.data.alerts.critical || criticalSeverity,
        highSeverity: statsRes.data.alerts.high || highSeverity,
        mediumSeverity: statsRes.data.alerts.medium || mediumSeverity,
        recentLogs: logData.slice(0, 5),
        health: healthRes.data,
      });
    } catch (err) {
      setError("Failed to load dashboard data");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": () => fetchStats(),
      "logs:new": () => fetchStats(),
    }),
    [fetchStats]
  );

  useSocket(token, socketHandlers);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 15000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  if (loading) return <MainLayout><div className="loading">Loading...</div></MainLayout>;

  return (
    <MainLayout>
      <h1>Dashboard</h1>
      <p>Real-time monitoring of network traffic and intrusion detection statistics.</p>

      {error && <div className="error-message">{error}</div>}

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Alerts</h3>
          <div className="stat-number">{stats.totalAlerts}</div>
        </div>
        <div className="stat-card critical">
          <h3>Critical Severity</h3>
          <div className="stat-number">{stats.criticalSeverity}</div>
        </div>
        <div className="stat-card high">
          <h3>High Severity</h3>
          <div className="stat-number">{stats.highSeverity}</div>
        </div>
        <div className="stat-card medium">
          <h3>Medium Severity</h3>
          <div className="stat-number">{stats.mediumSeverity}</div>
        </div>
        <div className="stat-card">
          <h3>System Status</h3>
          <div className="stat-number">
            {stats.health.idsEngine === "online" ? "✅ Active" : "⚠️ Degraded"}
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Recent Logs</h3>
        {stats.recentLogs.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Message</th>
                <th>Level</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentLogs.map((log, idx) => (
                <tr key={idx}>
                  <td>{log.message}</td>
                  <td className={`level-${log.level}`}>{log.level}</td>
                  <td>{new Date(log.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No logs yet.</p>
        )}
      </div>

      <button onClick={fetchStats} className="refresh-btn">
        🔄 Refresh
      </button>

      <div className="card">
        <h3>System Health</h3>
        <div className="health-grid">
          <div>
            <strong>Database:</strong> {stats.health.database}
          </div>
          <div>
            <strong>IDS Engine:</strong> {stats.health.idsEngine}
          </div>
          <div>
            <strong>Last Detection:</strong>{" "}
            {stats.health.lastDetectionTime
              ? new Date(stats.health.lastDetectionTime).toLocaleString()
              : "-"}
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default Dashboard;
