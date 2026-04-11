import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, logs } from "../services/api";
import useSocket from "../hooks/useSocket";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

const SEVERITY_COLORS = {
  Critical: "#ff5d73",
  High: "#ff8a3d",
  Medium: "#f4d35e",
  Low: "#38b000"
};

const PROTOCOL_COLORS = ["#3a86ff", "#00b4d8", "#4cc9f0", "#90e0ef", "#ffbe0b", "#fb5607"];

const formatCompact = (value) =>
  new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(
    Number(value || 0)
  );

const formatBytes = (value) => {
  const bytes = Number(value || 0);

  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${bytes} B`;
};

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalAlerts: 0,
    criticalSeverity: 0,
    highSeverity: 0,
    mediumSeverity: 0,
    lowSeverity: 0,
    recentLogs: [],
    topAttackTypes: [],
    topPorts: [],
    protocolDistribution: [],
    sourceCountries: [],
    destinationCountries: [],
    topSourceIps: [],
    timeline: [],
    traffic: {
      totalBytes: 0,
      avgDuration: 0,
      avgRequestRate: 0,
      totalFailedAttempts: 0,
      avgFlowCount: 0,
      eventsLast24h: 0
    },
    health: {
      database: "unknown",
      idsEngine: "unknown",
      lastDetectionTime: null
    }
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const token = localStorage.getItem("accessToken");
  const abortControllerRef = useRef(null);
  const refreshTimerRef = useRef(null);

  const fetchStats = useCallback(async () => {
    try {
      setError("");

      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      abortControllerRef.current = new AbortController();

      const [alertsRes, logsRes, statsRes, healthRes] = await Promise.allSettled([
        alerts.list(100),
        logs.list(12),
        dashboard.stats(),
        dashboard.health()
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
        alertsData.filter((item) => item.severity === level).length;

      setStats({
        totalAlerts: statsData?.alerts?.total ?? alertsData.length,
        criticalSeverity: statsData?.alerts?.critical ?? severityCount("Critical"),
        highSeverity: statsData?.alerts?.high ?? severityCount("High"),
        mediumSeverity: statsData?.alerts?.medium ?? severityCount("Medium"),
        lowSeverity: statsData?.alerts?.low ?? severityCount("Low"),
        recentLogs: logData.slice(0, 8),
        topAttackTypes: statsData?.analytics?.topAttackTypes ?? [],
        topPorts: statsData?.analytics?.topPorts ?? [],
        protocolDistribution: statsData?.analytics?.protocolDistribution ?? [],
        sourceCountries: statsData?.analytics?.sourceCountries ?? [],
        destinationCountries: statsData?.analytics?.destinationCountries ?? [],
        topSourceIps: statsData?.analytics?.topSourceIps ?? [],
        timeline: statsData?.analytics?.timeline ?? [],
        traffic: {
          totalBytes: statsData?.traffic?.totalBytes ?? 0,
          avgDuration: statsData?.traffic?.avgDuration ?? 0,
          avgRequestRate: statsData?.traffic?.avgRequestRate ?? 0,
          totalFailedAttempts: statsData?.traffic?.totalFailedAttempts ?? 0,
          avgFlowCount: statsData?.traffic?.avgFlowCount ?? 0,
          eventsLast24h: statsData?.traffic?.eventsLast24h ?? logData.length
        },
        health: {
          database: healthData?.database ?? "unknown",
          idsEngine: healthData?.idsEngine ?? "unknown",
          lastDetectionTime: healthData?.lastDetectionTime ?? null
        }
      });

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

  const severityStrip = useMemo(
    () => [
      {
        label: "Critical Severity",
        value: stats.criticalSeverity,
        tone: "critical",
        spark: stats.timeline.map((point) => ({
          time: point.time,
          value: point.events
        }))
      },
      {
        label: "High Severity",
        value: stats.highSeverity,
        tone: "high",
        spark: stats.timeline.map((point) => ({
          time: point.time,
          value: Math.round(point.requestRate || 0)
        }))
      },
      {
        label: "Medium Severity",
        value: stats.mediumSeverity,
        tone: "medium",
        spark: stats.timeline.map((point) => ({
          time: point.time,
          value: Math.round((point.bytes || 0) / 1024)
        }))
      },
      {
        label: "Low Severity",
        value: stats.lowSeverity,
        tone: "low",
        spark: stats.timeline.map((point) => ({
          time: point.time,
          value: point.events
        }))
      }
    ],
    [stats]
  );

  const healthTone =
    stats.health.idsEngine === "online"
      ? "healthy"
      : stats.health.idsEngine === "offline"
        ? "offline"
        : "degraded";

  const socketHandlers = useMemo(
    () => ({
      "alerts:new": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchStats, 300);
      },
      "logs:new": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchStats, 300);
      }
    }),
    [fetchStats]
  );

  useSocket(token, socketHandlers);

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

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading dashboard...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">Network / ThreatLens / SOC</div>
          <h1>Threat Operations Dashboard</h1>
          <p>
            Live visibility into severity, protocols, flow behavior, failed attempts,
            request-rate bursts, and top destinations.
          </p>
        </div>

        <div className={`status-pill ${healthTone}`}>
          <span className="status-dot" />
          IDS {stats.health.idsEngine}
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="severity-strip">
        {severityStrip.map((item) => (
          <div key={item.label} className={`severity-panel ${item.tone}`}>
            <div className="severity-head">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
            <div className="mini-chart">
              <ResponsiveContainer>
                <AreaChart data={item.spark}>
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke={SEVERITY_COLORS[item.label.split(" ")[0]] || "#00d4ff"}
                    fill={SEVERITY_COLORS[item.label.split(" ")[0]] || "#00d4ff"}
                    fillOpacity={0.2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        ))}
      </section>

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Total Alerts</span>
          <strong>{formatCompact(stats.totalAlerts)}</strong>
        </div>
        <div className="metric-card">
          <span>Events Last 24h</span>
          <strong>{formatCompact(stats.traffic.eventsLast24h)}</strong>
        </div>
        <div className="metric-card">
          <span>Total Bytes</span>
          <strong>{formatBytes(stats.traffic.totalBytes)}</strong>
        </div>
        <div className="metric-card">
          <span>Avg Duration</span>
          <strong>{stats.traffic.avgDuration}s</strong>
        </div>
        <div className="metric-card">
          <span>Avg Request Rate</span>
          <strong>{Math.round(stats.traffic.avgRequestRate)}/min</strong>
        </div>
        <div className="metric-card">
          <span>Failed Attempts</span>
          <strong>{formatCompact(stats.traffic.totalFailedAttempts)}</strong>
        </div>
        <div className="metric-card">
          <span>Avg Flow Count</span>
          <strong>{stats.traffic.avgFlowCount}</strong>
        </div>
        <div className="metric-card">
          <span>Last Detection</span>
          <strong>
            {stats.health.lastDetectionTime
              ? new Date(stats.health.lastDetectionTime).toLocaleTimeString()
              : "No alerts"}
          </strong>
        </div>
      </section>

      <section className="dashboard-grid">
        <div className="dashboard-panel panel-wide">
          <div className="panel-header">
            <h3>Traffic Volume & Request Rate</h3>
            <span>Last 24 hours</span>
          </div>
          <div className="panel-chart">
            <ResponsiveContainer>
              <LineChart data={stats.timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="time" stroke="#93a4c3" />
                <YAxis yAxisId="left" stroke="#93a4c3" />
                <YAxis yAxisId="right" orientation="right" stroke="#93a4c3" />
                <Tooltip />
                <Legend />
                <Line
                  yAxisId="left"
                  type="monotone"
                  dataKey="events"
                  stroke="#4cc9f0"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="requestRate"
                  stroke="#ffbe0b"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Protocols</h3>
            <span>Transport/Application mix</span>
          </div>
          <div className="panel-chart">
            <ResponsiveContainer>
              <PieChart>
                <Pie
                  data={stats.protocolDistribution}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={68}
                  outerRadius={100}
                  paddingAngle={4}
                >
                  {stats.protocolDistribution.map((entry, index) => (
                    <Cell key={entry.name} fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Alert Types</h3>
            <span>Detected threats</span>
          </div>
          <div className="panel-chart">
            <ResponsiveContainer>
              <BarChart data={stats.topAttackTypes} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis type="number" stroke="#93a4c3" />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#93a4c3"
                  width={130}
                  tick={{ fontSize: 11 }}
                />
                <Tooltip />
                <Bar dataKey="value" fill="#8ecae6" radius={[0, 8, 8, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Destination Ports</h3>
            <span>Most targeted services</span>
          </div>
          <div className="panel-chart">
            <ResponsiveContainer>
              <BarChart data={stats.topPorts}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="name" stroke="#93a4c3" />
                <YAxis allowDecimals={false} stroke="#93a4c3" />
                <Tooltip />
                <Bar dataKey="value" fill="#fb5607" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Source IPs</h3>
            <span>Most active senders</span>
          </div>
          <div className="panel-list">
            {stats.topSourceIps.length > 0 ? (
              stats.topSourceIps.map((item) => (
                <div key={item.name} className="list-row">
                  <span className="mono-text">{item.name}</span>
                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <p>No traffic sources yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Source Countries</h3>
            <span>Origin summary</span>
          </div>
          <div className="panel-list">
            {stats.sourceCountries.length > 0 ? (
              stats.sourceCountries.map((item) => (
                <div key={item.name} className="list-row">
                  <span>{item.name}</span>
                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <p>No source geography data yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Destination Countries</h3>
            <span>Outbound targets</span>
          </div>
          <div className="panel-list">
            {stats.destinationCountries.length > 0 ? (
              stats.destinationCountries.map((item) => (
                <div key={item.name} className="list-row">
                  <span>{item.name}</span>
                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <p>No destination geography data yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel panel-wide">
          <div className="panel-header">
            <h3>Recent Logs</h3>
            <span>Latest ingested network activity</span>
          </div>
          <div className="panel-table">
            {stats.recentLogs.length > 0 ? (
              <table>
                <thead>
                  <tr>
                    <th>Message</th>
                    <th>Protocol</th>
                    <th>Bytes</th>
                    <th>Dest Port</th>
                    <th>Req Rate</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recentLogs.map((log, index) => (
                    <tr key={log._id || index}>
                      <td>{log.message}</td>
                      <td>{log.metadata?.protocol || "-"}</td>
                      <td>{formatBytes(log.metadata?.bytes)}</td>
                      <td className="mono-text">
                        {log.metadata?.destinationPort || log.metadata?.port || "-"}
                      </td>
                      <td>{log.metadata?.requestRate || "-"}</td>
                      <td>
                        {log.timestamp ? new Date(log.timestamp).toLocaleString() : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p>No logs yet.</p>
            )}
          </div>
        </div>
      </section>

      <button onClick={fetchStats} className="refresh-btn">
        Refresh Dashboard
      </button>
    </MainLayout>
  );
};

export default Dashboard;
