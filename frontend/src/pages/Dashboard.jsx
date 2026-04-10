import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

  const abortControllerRef = useRef(null);

  /* ================= FETCH STATS ================= */

  const fetchStats = useCallback(async () => {
    try {
      setError("");

      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      abortControllerRef.current = new AbortController();

      const [alertsRes, logsRes, statsRes, healthRes] = await Promise.all([
        alerts.list(100),
        logs.list(10),
        dashboard.stats(),
        dashboard.health(),
      ]);

      const alertsData = alertsRes?.data?.data ?? [];
      const logData = logsRes?.data?.data ?? [];

      const severityCount = (level) =>
        alertsData.filter((a) => a.severity === level).length;

      setStats((prev) => ({
        ...prev,
        totalAlerts: statsRes?.data?.alerts?.total ?? alertsData.length,
        criticalSeverity:
          statsRes?.data?.alerts?.critical ?? severityCount("Critical"),
        highSeverity:
          statsRes?.data?.alerts?.high ?? severityCount("High"),
        mediumSeverity:
          statsRes?.data?.alerts?.medium ?? severityCount("Medium"),
        recentLogs: logData.slice(0, 5),
        health: {
          database: healthRes?.data?.database ?? "unknown",
          idsEngine: healthRes?.data?.idsEngine ?? "unknown",
          lastDetectionTime: healthRes?.data?.lastDetectionTime ?? null,
        },
      }));
    } catch (err) {
      console.error("Dashboard error:", err);
      setError("Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, []);

  /* ================= SOCKET HANDLERS ================= */

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": fetchStats,
      "logs:new": fetchStats,
    }),
    [fetchStats]
  );

  useSocket(token, socketHandlers);

  /* ================= INITIAL LOAD ================= */

  useEffect(() => {
    fetchStats();

    const interval = setInterval(() => {
      fetchStats();
    }, 15000);

    return () => {
      clearInterval(interval);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [fetchStats]);

  /* ================= LOADING UI ================= */

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading dashboard...</div>
      </MainLayout>
    );
  }

  /* ================= UI ================= */

  return (
    <MainLayout>
      <h1>Dashboard</h1>
      <p>
        Real-time monitoring of network traffic and intrusion detection
        statistics.
      </p>

      {error && <div className="error-message">{error}</div>}

      {/* ================= STATS GRID ================= */}

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
            {stats.health?.idsEngine === "online" ? "✅ Active" : "⚠️ Degraded"}
          </div>
        </div>
      </div>

      {/* ================= LOGS ================= */}

      <div className="card">
        <h3>Recent Logs</h3>

        {stats.recentLogs?.length > 0 ? (
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
                <tr key={log._id || idx}>
                  <td>{log.message}</td>
                  <td className={`level-${log.level}`}>{log.level}</td>
                  <td>
                    {log.timestamp
                      ? new Date(log.timestamp).toLocaleString()
                      : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No logs yet.</p>
        )}
      </div>

      {/* ================= REFRESH BUTTON ================= */}

      <button onClick={fetchStats} className="refresh-btn">
        🔄 Refresh
      </button>

      {/* ================= HEALTH ================= */}

      <div className="card">
        <h3>System Health</h3>

        <div className="health-grid">
          <div>
            <strong>Database:</strong> {stats.health?.database}
          </div>

          <div>
            <strong>IDS Engine:</strong> {stats.health?.idsEngine}
          </div>

          <div>
            <strong>Last Detection:</strong>{" "}
            {stats.health?.lastDetectionTime
              ? new Date(stats.health.lastDetectionTime).toLocaleString()
              : "-"}
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default Dashboard;