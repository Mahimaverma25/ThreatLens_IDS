import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, logs } from "../services/api";
import useSocket from "../hooks/useSocket";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend
} from "recharts";

const SEVERITY_COLORS = {
  Critical: "#d7263d",
  High: "#f46036",
  Medium: "#f6ae2d",
  Low: "#3da5d9"
};

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
  const refreshTimerRef = useRef(null);

  /* ================= FETCH STATS ================= */

  const fetchStats = useCallback(async () => {
    try {
      setError("");

      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      abortControllerRef.current = new AbortController();

      const [alertsRes, logsRes, statsRes, healthRes] = await Promise.allSettled([
        alerts.list(100),
        logs.list(10),
        dashboard.stats(),
        dashboard.health(),
      ]);

      const alertsData =
        alertsRes.status === "fulfilled" ? alertsRes.value?.data?.data ?? [] : [];
      const logData =
        logsRes.status === "fulfilled" ? logsRes.value?.data?.data ?? [] : [];
      const statsData =
        statsRes.status === "fulfilled" ? statsRes.value?.data ?? {} : {};
      const healthData =
        healthRes.status === "fulfilled" ? healthRes.value?.data ?? {} : {};

      const severityCount = (level) =>
        alertsData.filter((a) => a.severity === level).length;

      setStats((prev) => ({
        ...prev,
        totalAlerts: statsData?.alerts?.total ?? alertsData.length,
        criticalSeverity:
          statsData?.alerts?.critical ?? severityCount("Critical"),
        highSeverity:
          statsData?.alerts?.high ?? severityCount("High"),
        mediumSeverity:
          statsData?.alerts?.medium ?? severityCount("Medium"),
        recentLogs: logData.slice(0, 5),
        health: {
          database: healthData?.database ?? "unknown",
          idsEngine: healthData?.idsEngine ?? "unknown",
          lastDetectionTime: healthData?.lastDetectionTime ?? null,
        },
      }));

      const allRequestsFailed =
        alertsRes.status === "rejected" &&
        logsRes.status === "rejected" &&
        statsRes.status === "rejected" &&
        healthRes.status === "rejected";

      if (allRequestsFailed) {
        setError("Failed to load dashboard data");
      }
    } catch (err) {
      console.error("Dashboard error:", err);
      setError("Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, []);

  /* ================= SOCKET HANDLERS ================= */

  const severityChartData = useMemo(
    () => [
      { name: "Critical", value: stats.criticalSeverity },
      { name: "High", value: stats.highSeverity },
      { name: "Medium", value: stats.mediumSeverity },
      {
        name: "Low",
        value: Math.max(
          0,
          stats.totalAlerts - stats.criticalSeverity - stats.highSeverity - stats.mediumSeverity
        )
      }
    ],
    [stats]
  );

  const sourceChartData = useMemo(() => {
    const counts = stats.recentLogs.reduce((acc, log) => {
      const key = log.source || "unknown";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [stats.recentLogs]);

  const timelineData = useMemo(() => {
    const buckets = new Map();

    stats.recentLogs.forEach((log) => {
      if (!log.timestamp) {
        return;
      }

      const date = new Date(log.timestamp);
      const key = `${date.getHours()}:${String(date.getMinutes()).padStart(2, "0")}`;
      buckets.set(key, (buckets.get(key) || 0) + 1);
    });

    return [...buckets.entries()].map(([time, count]) => ({ time, count }));
  }, [stats.recentLogs]);

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchStats, 300);
      },
      "logs:new": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchStats, 300);
      },
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
      clearTimeout(refreshTimerRef.current);
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

      <div className="card">
        <h3>Threat Severity Distribution</h3>
        <div style={{ width: "100%", height: 300 }}>
          <ResponsiveContainer>
            <PieChart>
              <Pie
                data={severityChartData}
                dataKey="value"
                nameKey="name"
                innerRadius={65}
                outerRadius={100}
                paddingAngle={3}
              >
                {severityChartData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#999"} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <h3>Log Source Activity</h3>
        <div style={{ width: "100%", height: 300 }}>
          <ResponsiveContainer>
            <BarChart data={sourceChartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="value" fill="#2f7ed8" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <h3>Event Timeline (Recent)</h3>
        <div style={{ width: "100%", height: 280 }}>
          <ResponsiveContainer>
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Line type="monotone" dataKey="count" stroke="#16a34a" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
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
