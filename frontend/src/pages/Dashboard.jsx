import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, logs } from "../services/api";
import useSocket from "../hooks/useSocket";
import LiveOpsFeed from "../components/LiveOpsFeed";
import LiveTerminal from "../components/LiveTerminal";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const SEVERITY_COLORS = {
  Critical: "#ff5d73",
  High: "#ff9f43",
  Medium: "#ffd166",
  Low: "#4cd97b",
  Unknown: "#7c8aa5",
};

const PROTOCOL_COLORS = [
  "#48cae4",
  "#00b4d8",
  "#90e0ef",
  "#ffb703",
  "#fb8500",
  "#8ecae6",
];

const SOURCE_COLORS = [
  "#00d1ff",
  "#6ee7b7",
  "#fbbf24",
  "#fb7185",
  "#c084fc",
  "#38bdf8",
];

const defaultStats = {
  mode: "waiting-for-telemetry",
  totalAlerts: 0,
  criticalSeverity: 0,
  highSeverity: 0,
  mediumSeverity: 0,
  lowSeverity: 0,
  recentLogs: [],
  recentAlerts: [],
  topAttackTypes: [],
  topPorts: [],
  protocolDistribution: [],
  classifications: [],
  alertSourceDistribution: [],
  alertStatusDistribution: [],
  severityDistribution: [],
  topSourceIps: [],
  topDestinationIps: [],
  timeline: [],
  traffic: {
    eventsLast24h: 0,
    uniqueSourceIps: 0,
    uniqueDestinationIps: 0,
    avgPriority: 0,
    liveSnortEventsLast24h: 0,
    liveSnortAlertsLast24h: 0,
    hostEventsLast24h: 0,
    hostAlertsLast24h: 0,
    mlAnomaliesLast24h: 0,
    telemetryCoverage: {
      total: 0,
      withProtocol: 0,
      withDestination: 0,
      withPort: 0,
      unknownProtocol: 0,
      unknownDestination: 0,
      unknownPort: 0,
    },
    networkCoverage: {
      total: 0,
      withProtocol: 0,
      withDestination: 0,
      withPort: 0,
      unknownProtocol: 0,
      unknownDestination: 0,
      unknownPort: 0,
    },
  },
  health: {
    database: "unknown",
    idsEngine: "unknown",
    snort: "unknown",
    host: "unknown",
    collector: {
      status: "unknown",
      lastHeartbeatAt: null,
      agentType: null,
      hostPlatform: "",
      hostname: "",
      queueDepth: 0,
      telemetryTypes: [],
    },
    stream: {
      mode: "memory",
      connected: false,
      lastPublishedAt: null,
    },
    lastDetectionTime: null,
    liveSnortEventsLast24h: 0,
    liveHostEventsLast24h: 0,
    snortLastEventAt: null,
    hostLastEventAt: null,
    modelLoaded: null,
    usingFallback: null,
  },
};

const safeArray = (value) => (Array.isArray(value) ? value : []);

const safeStatus = (value) => {
  if (!value) return "unknown";
  return String(value).trim().toLowerCase();
};

const formatCompact = (value) =>
  new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(Object.is(Number(value || 0), -0) ? 0 : Math.max(0, Number(value || 0)));

const formatDateTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const formatTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleTimeString();
};

const titleCase = (value) => {
  if (!value) return "Unknown";
  return String(value)
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
};

const isUnknownLike = (value) => {
  if (value === null || value === undefined) return true;
  const normalized = String(value).trim().toLowerCase();
  return (
    !normalized ||
    normalized === "unknown" ||
    normalized === "n/a" ||
    normalized === "-"
  );
};

const hasMeaningfulValue = (value) => !isUnknownLike(value);

const hasKnownPort = (value) => {
  const normalized = String(value || "").trim();
  return (
    Boolean(normalized) &&
    normalized !== "Unknown" &&
    !normalized.startsWith("N/A")
  );
};

const getMessage = (log) =>
  log?.derived?.message ||
  log?.metadata?.snort?.message ||
  log?.message ||
  log?.signature ||
  "Unknown Event";

const getProtocol = (log) =>
  log?.derived?.protocol ||
  log?.metadata?.protocol ||
  log?.metadata?.appProtocol ||
  log?.metadata?.snort?.protocol ||
  log?.protocol ||
  "Unknown";

const getPriority = (log) => {
  const raw =
    log?.derived?.priority ??
    log?.metadata?.snort?.priority ??
    log?.priority ??
    log?.severityScore ??
    0;

  const numeric = Number(raw);
  return Number.isNaN(numeric) ? 0 : numeric;
};

const getSrcIp = (log) =>
  log?.derived?.srcIp ||
  log?.metadata?.snort?.srcIp ||
  log?.srcIp ||
  log?.sourceIp ||
  log?.ip ||
  "-";

const getDestIp = (log) =>
  log?.derived?.destIp ||
  log?.metadata?.snort?.destIp ||
  log?.destIp ||
  log?.destinationIp ||
  "-";

const getDestPort = (log) => {
  const protocol = String(getProtocol(log)).toUpperCase();
  const value =
    log?.derived?.destPort ??
    log?.metadata?.snort?.destPort ??
    log?.metadata?.destinationPort ??
    log?.metadata?.port ??
    log?.destPort ??
    log?.destinationPort ??
    null;

  if (value !== null && value !== undefined && String(value).trim() !== "") {
    return String(value);
  }

  if (protocol.includes("ICMP")) return "N/A (ICMP)";
  return "Unknown";
};

const deriveClassification = (log) => {
  const explicit =
    log?.derived?.classification ||
    log?.metadata?.snort?.classification ||
    log?.classification ||
    log?.metadata?.classification;

  if (!isUnknownLike(explicit)) {
    return titleCase(explicit);
  }

  const message = getMessage(log).toLowerCase();
  const protocol = String(getProtocol(log)).toLowerCase();

  if (message.includes("sql")) return "SQL Injection";
  if (message.includes("xss")) return "XSS Attempt";
  if (message.includes("brute") || message.includes("login"))
    return "Brute Force";
  if (message.includes("scan")) return "Recon / Scan";
  if (
    message.includes("flood") ||
    message.includes("ddos") ||
    message.includes("dos")
  ) {
    return "DoS / Flood";
  }
  if (message.includes("trojan") || message.includes("malware"))
    return "Malware Activity";
  if (protocol.includes("icmp")) return "ICMP Activity";
  if (protocol.includes("udp")) return "UDP Activity";
  if (protocol.includes("tcp")) return "TCP Activity";

  return "General Threat";
};

const deriveLog = (log) => ({
  ...log,
  derivedMessage: getMessage(log),
  derivedProtocol: getProtocol(log),
  derivedDestPort: getDestPort(log),
  derivedSrcIp: getSrcIp(log),
  derivedDestIp: getDestIp(log),
  derivedPriority: getPriority(log),
  derivedClassification: deriveClassification(log),
});

const buildBuckets = (items, keyGetter, limit = 6) => {
  const counts = new Map();

  items.forEach((item) => {
    const rawKey = keyGetter(item);
    const key = isUnknownLike(rawKey) ? "Unknown" : String(rawKey).trim();
    counts.set(key, (counts.get(key) || 0) + 1);
  });

  return Array.from(counts.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, limit);
};

const shortenLabel = (value, maxLength = 18) => {
  const text = String(value || "");
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 1)}…`;
};

const isNetworkTelemetryLog = (log) => {
  const source = safeStatus(log?.metadata?.sensorType || log?.source);
  return source === "snort" || source === "suricata";
};

const buildCoverage = (items) => {
  const total = items.length;
  const withProtocol = items.filter((item) => hasMeaningfulValue(item.derivedProtocol)).length;
  const withDestination = items.filter((item) => hasMeaningfulValue(item.derivedDestIp)).length;
  const withPort = items.filter((item) => hasKnownPort(item.derivedDestPort)).length;

  return {
    total,
    withProtocol,
    withDestination,
    withPort,
    unknownProtocol: Math.max(0, total - withProtocol),
    unknownDestination: Math.max(0, total - withDestination),
    unknownPort: Math.max(0, total - withPort),
  };
};

const deriveModelLabel = (health) => {
  const idsStatus = safeStatus(health?.idsEngine);
  if (idsStatus === "offline") return "Unavailable";
  if (health?.modelLoaded === true) {
    return health?.usingFallback ? "Fallback Model" : "Random Forest Loaded";
  }
  if (health?.modelLoaded === false) return "Rules Only";
  return "Unknown";
};

const getStatusTone = (value) => {
  const normalized = safeStatus(value);
  if (
    normalized === "online" ||
    normalized === "ok" ||
    normalized === "connected"
  ) {
    return "healthy";
  }
  if (normalized === "offline" || normalized === "disconnected") {
    return "offline";
  }
  return "degraded";
};

const Dashboard = () => {
  const [stats, setStats] = useState(defaultStats);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [liveOpsFeed, setLiveOpsFeed] = useState([]);
  const [liveLogs, setLiveLogs] = useState([]);

  const token = localStorage.getItem("accessToken");
  const refreshTimerRef = useRef(null);
  const pollingRef = useRef(null);
  const lastRefreshRequestRef = useRef(0);
  const isMountedRef = useRef(true);
  const fetchingRef = useRef(false);

  const fetchStats = useCallback(async (silent = false) => {
    if (fetchingRef.current) return;
    fetchingRef.current = true;

    try {
      if (!silent) setError("");

      const [alertsRes, logsRes, statsRes, healthRes] =
        await Promise.allSettled([
          alerts.list(100, 1),
          logs.list(80, 1),
          dashboard.stats(),
          dashboard.health(),
        ]);

      const alertsData =
        alertsRes.status === "fulfilled"
          ? safeArray(alertsRes.value?.data?.data)
          : [];

      const logData =
        logsRes.status === "fulfilled"
          ? safeArray(logsRes.value?.data?.data).map(deriveLog)
          : [];

      const statsData =
        statsRes.status === "fulfilled" ? (statsRes.value?.data ?? {}) : {};

      const healthData =
        healthRes.status === "fulfilled" ? (healthRes.value?.data ?? {}) : {};

      const apiRecentLogs = safeArray(statsData?.analytics?.recentLogs).map(
        deriveLog
      );

      const recentLogs =
        apiRecentLogs.length > 0 ? apiRecentLogs.slice(0, 12) : logData.slice(0, 12);

      const recentAlerts = safeArray(statsData?.analytics?.recentAlerts).length
        ? safeArray(statsData?.analytics?.recentAlerts).slice(0, 8)
        : alertsData.slice(0, 8);

      const snortLogs = logData.filter(isNetworkTelemetryLog);
      const hostLogs = logData.filter(
        (log) => safeStatus(log?.metadata?.sensorType || log?.source) === "host"
      );
      const networkCoverage = buildCoverage(snortLogs);

      const fallbackProtocolDistribution = buildBuckets(
        snortLogs.filter((log) => hasMeaningfulValue(log.derivedProtocol)),
        (log) => log.derivedProtocol,
        6
      );

      const fallbackTopPorts = buildBuckets(
        snortLogs.filter((log) => hasKnownPort(log.derivedDestPort)),
        (log) => log.derivedDestPort,
        8
      );

      const fallbackTopThreats = buildBuckets(
        alertsData,
        (item) => item?.attackType || item?.type,
        8
      ).filter((item) => !isUnknownLike(item.name));

      const fallbackTopSourceIps = buildBuckets(
        logData.filter((log) => hasMeaningfulValue(log.derivedSrcIp)),
        (log) => log.derivedSrcIp,
        8
      );

      const fallbackTopDestinationIps = buildBuckets(
        snortLogs.filter((log) => hasMeaningfulValue(log.derivedDestIp)),
        (log) => log.derivedDestIp,
        8
      );

      const fallbackAlertSourceDistribution = buildBuckets(
        alertsData,
        (alert) => alert?.source || "unknown"
      );

      const fallbackSeverityDistribution = buildBuckets(
        alertsData,
        (alert) => alert?.severity || "Unknown",
        6
      );

      const uniqueSourceIps = new Set(
        logData
          .map((log) => log.derivedSrcIp)
          .filter((value) => !isUnknownLike(value))
      ).size;

      const uniqueDestinationIps = new Set(
        logData
          .map((log) => log.derivedDestIp)
          .filter((value) => !isUnknownLike(value))
      ).size;

      const avgPriority =
        logData.length > 0
          ? logData.reduce((sum, log) => sum + log.derivedPriority, 0) /
            logData.length
          : 0;

      const nextHealth = {
        database: safeStatus(healthData?.database),
        idsEngine: safeStatus(
          healthData?.idsEngine?.status ?? healthData?.idsEngine
        ),
        snort: safeStatus(
          healthData?.snort?.status ??
            (snortLogs.length > 0 ? "online" : "unknown")
        ),
        host: safeStatus(healthData?.host?.status),
        lastDetectionTime:
          healthData?.lastDetectionTime ??
          recentAlerts?.[0]?.timestamp ??
          recentLogs?.[0]?.timestamp ??
          null,
        liveSnortEventsLast24h:
          healthData?.snort?.liveEventsLast24h ?? snortLogs.length,
        liveHostEventsLast24h:
          healthData?.host?.liveEventsLast24h ?? 0,
        snortLastEventAt:
          healthData?.snort?.lastEventAt ?? snortLogs?.[0]?.timestamp ?? null,
        hostLastEventAt:
          healthData?.host?.lastEventAt ?? null,
        modelLoaded:
          healthData?.idsEngine?.modelLoaded === null ||
          healthData?.idsEngine?.modelLoaded === undefined
            ? null
            : Boolean(healthData?.idsEngine?.modelLoaded),
        usingFallback:
          healthData?.idsEngine?.usingFallback === null ||
          healthData?.idsEngine?.usingFallback === undefined
            ? null
            : Boolean(healthData?.idsEngine?.usingFallback),
        collector: {
          status: safeStatus(healthData?.collector?.status),
          lastHeartbeatAt: healthData?.collector?.lastHeartbeatAt || null,
          agentType: healthData?.collector?.agentType || null,
          hostPlatform: healthData?.collector?.hostPlatform || "",
          hostname: healthData?.collector?.hostname || "",
          queueDepth: Number(healthData?.collector?.queueDepth || 0),
          telemetryTypes: Array.isArray(healthData?.collector?.telemetryTypes)
            ? healthData.collector.telemetryTypes
            : [],
        },
        stream: {
          mode: healthData?.stream?.mode || "memory",
          connected: Boolean(healthData?.stream?.connected),
          lastPublishedAt: healthData?.stream?.lastPublishedAt || null,
        },
      };

      const severityCount = (level) =>
        alertsData.filter(
          (item) => safeStatus(item?.severity) === safeStatus(level)
        ).length;

      const allRequestsFailed =
        alertsRes.status === "rejected" &&
        logsRes.status === "rejected" &&
        statsRes.status === "rejected" &&
        healthRes.status === "rejected";

      const nextStats = {
        mode:
          statsData?.mode ||
          (logData.length > 0 || alertsData.length > 0
            ? "live-monitoring"
            : "waiting-for-telemetry"),
        totalAlerts: statsData?.alerts?.total ?? alertsData.length,
        criticalSeverity:
          statsData?.alerts?.critical ?? severityCount("Critical"),
        highSeverity: statsData?.alerts?.high ?? severityCount("High"),
        mediumSeverity: statsData?.alerts?.medium ?? severityCount("Medium"),
        lowSeverity: statsData?.alerts?.low ?? severityCount("Low"),
        recentLogs,
        recentAlerts,
        topAttackTypes: safeArray(statsData?.analytics?.topAttackTypes).length
          ? safeArray(statsData?.analytics?.topAttackTypes)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackTopThreats,
        topPorts: safeArray(statsData?.analytics?.topPorts).length
          ? safeArray(statsData?.analytics?.topPorts)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackTopPorts,
        protocolDistribution: safeArray(
          statsData?.analytics?.protocolDistribution
        ).length
          ? safeArray(statsData?.analytics?.protocolDistribution)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackProtocolDistribution,
        alertSourceDistribution: safeArray(
          statsData?.analytics?.alertSourceDistribution
        ).length
          ? safeArray(statsData?.analytics?.alertSourceDistribution)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackAlertSourceDistribution,
        severityDistribution: safeArray(
          statsData?.analytics?.severityDistribution
        ).length
          ? safeArray(statsData?.analytics?.severityDistribution).slice(0, 6)
          : fallbackSeverityDistribution,
        topSourceIps: safeArray(statsData?.analytics?.topSourceIps).length
          ? safeArray(statsData?.analytics?.topSourceIps)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackTopSourceIps,
        topDestinationIps: safeArray(statsData?.analytics?.topDestinationIps)
          .length
          ? safeArray(statsData?.analytics?.topDestinationIps)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackTopDestinationIps,
        timeline: safeArray(statsData?.analytics?.timeline),
        traffic: {
          eventsLast24h: statsData?.traffic?.eventsLast24h ?? logData.length,
          uniqueSourceIps:
            statsData?.traffic?.uniqueSourceIps ?? uniqueSourceIps,
          uniqueDestinationIps:
            statsData?.traffic?.uniqueDestinationIps ?? uniqueDestinationIps,
          avgPriority: statsData?.traffic?.avgPriority ?? avgPriority,
          liveSnortEventsLast24h:
            statsData?.traffic?.liveSnortEventsLast24h ?? snortLogs.length,
          hostEventsLast24h:
            statsData?.traffic?.hostEventsLast24h ?? hostLogs.length,
          liveSnortAlertsLast24h:
            statsData?.traffic?.liveSnortAlertsLast24h ??
            alertsData.filter((alert) => safeStatus(alert.source) === "snort")
              .length,
          hostAlertsLast24h:
            statsData?.traffic?.hostAlertsLast24h ?? 0,
          mlAnomaliesLast24h:
            statsData?.traffic?.mlAnomaliesLast24h ??
            logData.filter((log) => Boolean(log?.metadata?.idsEngine?.is_anomaly))
              .length,
          telemetryCoverage: statsData?.traffic?.telemetryCoverage ?? {
            total: logData.length,
            withProtocol: logData.filter((log) =>
              hasMeaningfulValue(log.derivedProtocol)
            ).length,
            withDestination: logData.filter((log) =>
              hasMeaningfulValue(log.derivedDestIp)
            ).length,
            withPort: logData.filter((log) => hasKnownPort(log.derivedDestPort))
              .length,
            unknownProtocol: logData.filter(
              (log) => !hasMeaningfulValue(log.derivedProtocol)
            ).length,
            unknownDestination: logData.filter(
              (log) => !hasMeaningfulValue(log.derivedDestIp)
            ).length,
            unknownPort: logData.filter(
              (log) => !hasKnownPort(log.derivedDestPort)
            ).length,
          },
          networkCoverage,
        },
        health: nextHealth,
      };

      if (isMountedRef.current) {
        setStats(nextStats);
        setLastUpdated(new Date());
        setError(allRequestsFailed ? "Failed to load live dashboard data" : "");
        setLoading(false);
      }
    } catch (fetchError) {
      console.error("Dashboard fetch error:", fetchError);
      if (isMountedRef.current) {
        setError("Failed to load live dashboard data");
        setLoading(false);
      }
    } finally {
      fetchingRef.current = false;
    }
  }, []);

  const triggerRefresh = useCallback(() => {
    const now = Date.now();
    if (now - lastRefreshRequestRef.current < 1500) {
      return;
    }
    lastRefreshRequestRef.current = now;

    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      fetchStats(true);
    }, 300);
  }, [fetchStats]);

  const socketHandlers = useMemo(
    () => ({
      "socket:ready": () => {
        setLiveOpsFeed((current) => [
          {
            id: `socket-ready-${Date.now()}`,
            label: "Socket session established",
            meta: "Dashboard subscribed to the real-time channel",
            timestamp: new Date().toISOString(),
          },
          ...current,
        ].slice(0, 8));
      },
      "alerts:new": triggerRefresh,
      "alerts:update": triggerRefresh,
      "log:new": (event) => {
        const newLog = event?.data || event;
        if (newLog) {
          setLiveLogs((current) => [...current, newLog].slice(-50));
        }
        triggerRefresh();
      },
      "dashboard:update": triggerRefresh,
      "collector:heartbeat": (event) => {
        const heartbeat = event?.data || event || {};
        setStats((current) => ({
          ...current,
          health: {
            ...current.health,
            collector: {
              ...current.health.collector,
              status: safeStatus(heartbeat.status),
              lastHeartbeatAt: heartbeat.receivedAt || event?.timestamp || new Date().toISOString(),
              agentType: heartbeat.agentType || current.health.collector.agentType,
              hostPlatform: heartbeat.hostPlatform || current.health.collector.hostPlatform,
              hostname: heartbeat.hostname || current.health.collector.hostname,
              queueDepth: Number(heartbeat.queueDepth || 0),
              telemetryTypes: Array.isArray(heartbeat.telemetryTypes)
                ? heartbeat.telemetryTypes
                : current.health.collector.telemetryTypes,
            },
          },
        }));
        setLiveOpsFeed((current) => [
          {
            id: `heartbeat-${event?.timestamp || Date.now()}`,
            label: "Collector heartbeat",
            meta: `${heartbeat.status || "unknown"} / ${heartbeat.agentType || "collector"} / queue ${heartbeat.queueDepth || 0}`,
            timestamp: heartbeat.receivedAt || event?.timestamp || new Date().toISOString(),
          },
          ...current,
        ].slice(0, 8));
      },
      "stream:event": (event) => {
        setLiveOpsFeed((current) => [
          {
            id: `${event?.type || "stream"}-${event?.timestamp || Date.now()}`,
            label: event?.type || "Stream event",
            meta: `${event?.source || "pipeline"} / inserted ${event?.insertedCount || 0} / duplicates ${event?.duplicateCount || 0}`,
            timestamp: event?.timestamp || new Date().toISOString(),
          },
          ...current,
        ].slice(0, 8));
        triggerRefresh();
      },
    }),
    [triggerRefresh]
  );

  const socketState = useSocket(token, socketHandlers);

  useEffect(() => {
    isMountedRef.current = true;
    fetchStats();

    pollingRef.current = setInterval(() => {
      if (
        document.visibilityState === "visible" &&
        socketState.connectionStatus !== "connected"
      ) {
        fetchStats(true);
      }
    }, 30000);

    return () => {
      isMountedRef.current = false;
      clearInterval(pollingRef.current);
      clearTimeout(refreshTimerRef.current);
    };
  }, [fetchStats, socketState.connectionStatus]);

  const heroMetrics = useMemo(
    () => [
      {
        label: "Total Alerts",
        value: formatCompact(stats.totalAlerts),
        note: "Correlated detection volume",
      },
      {
        label: "Events 24h",
        value: formatCompact(stats.traffic.eventsLast24h),
        note: "Total telemetry observed",
      },
      {
        label: "Host Events",
        value: formatCompact(stats.traffic.hostEventsLast24h),
        note: "Endpoint telemetry",
      },
      {
        label: "ML Anomalies",
        value: formatCompact(stats.traffic.mlAnomaliesLast24h),
        note: "Model-flagged events",
      },
      {
        label: "Source IPs",
        value: formatCompact(stats.traffic.uniqueSourceIps),
        note: "Unique senders",
      },
      {
        label: "Destination IPs",
        value: formatCompact(stats.traffic.uniqueDestinationIps),
        note: "Targeted hosts",
      },
      {
        label: "Avg Priority",
        value: stats.traffic.avgPriority
          ? Number(stats.traffic.avgPriority).toFixed(1)
          : "-",
        note: "Snort severity baseline",
      },
      {
        label: "Tracked Protocols",
        value: formatCompact(stats.protocolDistribution.length),
        note: "Across the last 24h",
      },
    ],
    [stats]
  );

  const overviewMetrics = useMemo(
    () => [
      {
        label: "Live Mode",
        value: stats.mode === "live-monitoring" ? "Active" : "Waiting",
        note:
          stats.mode === "live-monitoring"
            ? "Telemetry is flowing"
            : "No fresh traffic yet",
      },
      {
        label: "Endpoint Detections",
        value: formatCompact(stats.traffic.hostAlertsLast24h),
        note:
          stats.traffic.hostAlertsLast24h > 0
            ? "Host alerts generated"
            : stats.traffic.hostEventsLast24h > 0
              ? "HIDS active, no host alerts yet"
              : "Waiting for host detections",
      },
      {
        label: "Model State",
        value: deriveModelLabel(stats.health),
        note: "Engine readiness",
      },
    ],
    [stats]
  );

  const telemetryQualityMetrics = useMemo(
    () => {
      const coverage = stats.traffic.networkCoverage;
      const isInactive = coverage.total === 0;

      return [
        {
          label: "Protocol Coverage",
          value: isInactive ? "N/A" : formatCompact(coverage.withProtocol),
          note: isInactive
            ? "NIDS inactive or no enriched network events"
            : `${formatCompact(coverage.unknownProtocol)} missing`,
        },
        {
          label: "Destination Coverage",
          value: isInactive ? "N/A" : formatCompact(coverage.withDestination),
          note: isInactive
            ? "NIDS inactive or no network destinations yet"
            : `${formatCompact(coverage.unknownDestination)} missing`,
        },
        {
          label: "Port Coverage",
          value: isInactive ? "N/A" : formatCompact(coverage.withPort),
          note: isInactive
            ? "NIDS inactive or no port-enriched events"
            : `${formatCompact(coverage.unknownPort)} missing`,
        },
      ];
    },
    [stats]
  );

  const controlCards = useMemo(
    () => [
      {
        label: "Socket Gateway",
        value: titleCase(socketState.connectionStatus),
        meta:
          socketState.connectionStatus === "connected"
            ? "Live dashboard subscription active"
            : socketState.lastError || "Waiting for live channel",
        tone: getStatusTone(
          socketState.connectionStatus === "connected"
            ? "connected"
            : socketState.connectionStatus
        ),
      },
      {
        label: "Collector",
        value: titleCase(stats.health.collector.status),
        meta: stats.health.collector.lastHeartbeatAt
          ? `Last heartbeat ${formatTime(stats.health.collector.lastHeartbeatAt)}`
          : "Waiting for collector heartbeat",
        tone: getStatusTone(stats.health.collector.status),
      },
      {
        label: "Host Telemetry",
        value: titleCase(stats.health.host),
        meta: stats.health.hostLastEventAt
          ? `Last host event ${formatTime(stats.health.hostLastEventAt)}`
          : "Waiting for host telemetry",
        tone: getStatusTone(stats.health.host),
      },
      {
        label: "Database",
        value: titleCase(stats.health.database),
        meta: "Persistence layer",
        tone: getStatusTone(stats.health.database),
      },
      {
        label: "Network IDS",
        value: titleCase(stats.health.snort),
        meta: stats.health.snortLastEventAt
          ? `Last IDS event ${formatTime(stats.health.snortLastEventAt)}`
          : "Waiting for IDS data",
        tone: getStatusTone(stats.health.snort),
      },
      {
        label: "IDS Engine",
        value: titleCase(stats.health.idsEngine),
        meta: deriveModelLabel(stats.health),
        tone: getStatusTone(stats.health.idsEngine),
      },
      {
        label: "Event Stream",
        value: stats.health.stream.connected
          ? titleCase(stats.health.stream.mode)
          : "Fallback",
        meta: stats.health.stream.lastPublishedAt
          ? `Last publish ${formatTime(stats.health.stream.lastPublishedAt)}`
          : "Waiting for stream events",
        tone: stats.health.stream.connected ? "healthy" : "degraded",
      },
    ],
    [socketState.connectionStatus, socketState.lastError, stats]
  );

  const alertSeverities = useMemo(
    () => [
      {
        label: "Critical",
        value: stats.criticalSeverity,
        color: SEVERITY_COLORS.Critical,
      },
      {
        label: "High",
        value: stats.highSeverity,
        color: SEVERITY_COLORS.High,
      },
      {
        label: "Medium",
        value: stats.mediumSeverity,
        color: SEVERITY_COLORS.Medium,
      },
      {
        label: "Low",
        value: stats.lowSeverity,
        color: SEVERITY_COLORS.Low,
      },
    ],
    [stats]
  );

  const healthTone = getStatusTone(stats.health.snort);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading dashboard...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="dashboard-hero">
        <div className="dashboard-hero__left">
          <div className="command-eyebrow">
            ThreatLens / SOC / Real-Time Operations
          </div>
          <h1>Threat Operations Dashboard</h1>
          <p>
            Live visibility across host telemetry, correlated incidents, supporting IDS signals, and platform health.
          </p>
          <div className="dashboard-hero__meta">
            <span>
              Last updated:{" "}
              {lastUpdated ? lastUpdated.toLocaleTimeString() : "Never"}
            </span>
            <span>
              Last detection: {formatTime(stats.health.lastDetectionTime)}
            </span>
            <span>
              Last heartbeat: {formatTime(stats.health.collector.lastHeartbeatAt)}
            </span>
            <span>
              Last host event: {formatTime(stats.health.hostLastEventAt)}
            </span>
          </div>
        </div>

        <div className={`status-pill ${healthTone}`}>
          <span className="status-dot" />
          {stats.mode === "live-monitoring"
            ? "Live monitoring active"
            : "Waiting for telemetry"}
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="hero-metric-grid">
        {heroMetrics.map((item) => (
          <div key={item.label} className="hero-metric-card">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            <small>{item.note}</small>
          </div>
        ))}
      </section>

      <section className="ops-strip">
        {controlCards.map((card) => (
          <div key={card.label} className={`ops-card ops-card--${card.tone}`}>
            <span className="ops-card__label">{card.label}</span>
            <strong>{card.value}</strong>
            <small>{card.meta}</small>
          </div>
        ))}
      </section>

      <section className="severity-strip">
        {alertSeverities.map((item) => {
          const totalSeverity =
            stats.criticalSeverity +
            stats.highSeverity +
            stats.mediumSeverity +
            stats.lowSeverity;

          const percent =
            totalSeverity > 0 ? (item.value / totalSeverity) * 100 : 0;

          return (
            <div key={item.label} className="severity-panel">
              <div className="severity-head">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
              <div className="severity-progress">
                <span
                  style={{
                    width: `${Math.max(8, Math.min(100, percent || 8))}%`,
                    background: item.color,
                  }}
                />
              </div>
            </div>
          );
        })}
      </section>

      <section className="metrics-grid metrics-grid--equal">
        {overviewMetrics.map((item) => (
          <div key={item.label} className="metric-card metric-card--fixed">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            <small>{item.note}</small>
          </div>
        ))}
      </section>

      <section className="metrics-grid telemetry-quality-grid">
        {telemetryQualityMetrics.map((item) => (
          <div key={item.label} className="metric-card metric-card--subtle">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            <small>{item.note}</small>
          </div>
        ))}
      </section>

      <section className="dashboard-grid dashboard-grid--premium">
        <div className="panel-span-2">
          <LiveTerminal logs={liveLogs} />
        </div>
        <LiveOpsFeed events={liveOpsFeed} />
      </section>

      <section className="dashboard-grid dashboard-grid--premium">
        <div className="dashboard-panel panel-span-2">
          <div className="panel-header">
            <h3>Event Activity Timeline</h3>
            <span>Last 24 hours of telemetry</span>
          </div>
          <div className="panel-chart panel-chart--lg">
            {stats.timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={stats.timeline}
                  margin={{ top: 12, right: 16, left: 0, bottom: 0 }}
                >
                  <defs>
                    <linearGradient
                      id="eventsGradient"
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >
                      <stop
                        offset="5%"
                        stopColor="#48cae4"
                        stopOpacity={0.85}
                      />
                      <stop
                        offset="95%"
                        stopColor="#48cae4"
                        stopOpacity={0.05}
                      />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.08)"
                  />
                  <XAxis dataKey="time" stroke="#93a4c3" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#93a4c3" tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="events"
                    stroke="#48cae4"
                    fill="url(#eventsGradient)"
                    strokeWidth={2.5}
                    name="Events"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <p>No telemetry has been ingested yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Protocol Mix</h3>
            <span>Observed traffic families</span>
          </div>
          <div className="panel-chart panel-chart--protocol">
            {stats.protocolDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.protocolDistribution}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={52}
                    outerRadius={82}
                    paddingAngle={3}
                  >
                    {stats.protocolDistribution.map((entry, index) => (
                      <Cell
                        key={`${entry.name}-${index}`}
                        fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <p>No enriched network protocol telemetry yet.</p>
            )}
          </div>
          <div className="panel-footnote">
            {stats.traffic.networkCoverage.total > 0
              ? `${formatCompact(stats.traffic.networkCoverage.unknownProtocol)} network events are missing protocol metadata.`
              : "NIDS is not active yet, so protocol coverage is not available."}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Threats</h3>
            <span>Most frequent detections</span>
          </div>
          <div className="panel-chart">
            {stats.topAttackTypes.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={stats.topAttackTypes}
                  layout="vertical"
                  margin={{ top: 4, right: 18, left: 32, bottom: 4 }}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.08)"
                  />
                  <XAxis type="number" stroke="#93a4c3" />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tickFormatter={(value) => shortenLabel(value, 20)}
                    stroke="#93a4c3"
                    width={150}
                    tick={{ fontSize: 11 }}
                  />
                  <Tooltip />
                  <Bar
                    dataKey="value"
                    fill="#7dd3fc"
                    radius={[0, 8, 8, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p>No threat activity recorded yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Alert Source</h3>
            <span>Snort, ML, and rule engine mix</span>
          </div>
          <div className="panel-chart">
            {stats.alertSourceDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={stats.alertSourceDistribution}
                  layout="vertical"
                  margin={{ top: 4, right: 18, left: 24, bottom: 4 }}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.08)"
                  />
                  <XAxis type="number" allowDecimals={false} stroke="#93a4c3" />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#93a4c3"
                    width={120}
                    tick={{ fontSize: 11 }}
                    tickFormatter={(value) => shortenLabel(titleCase(value), 16)}
                  />
                  <Tooltip
                    formatter={(value) => [value, "Alerts"]}
                    labelFormatter={titleCase}
                  />
                  <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                    {stats.alertSourceDistribution.map((entry, index) => (
                      <Cell
                        key={`${entry.name}-${index}`}
                        fill={SOURCE_COLORS[index % SOURCE_COLORS.length]}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p>No alert source data yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Most Targeted Services</h3>
            <span>Destination port concentration</span>
          </div>
          <div className="panel-list">
            {stats.topPorts.length > 0 ? (
              stats.topPorts.map((item, index) => (
                <div
                  key={`${item.name}-${index}`}
                  className="list-row list-row--pill"
                >
                  <span className="mono-text">{item.name}</span>
                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <p>No enriched service telemetry yet.</p>
            )}
          </div>
          <div className="panel-footnote">
            {stats.traffic.networkCoverage.total > 0
              ? `${formatCompact(stats.traffic.networkCoverage.unknownPort)} network events have no destination port.`
              : "NIDS is not active yet, so service and port coverage are not available."}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Live Operations Feed</h3>
            <span>Socket and stream pipeline activity</span>
          </div>
          <div className="panel-list">
            {liveOpsFeed.length > 0 ? (
              liveOpsFeed.map((item) => (
                <div key={item.id} className="list-row list-row-stack recent-alert-card">
                  <div className="list-row__top">
                    <span>{item.label}</span>
                    <strong>{formatTime(item.timestamp)}</strong>
                  </div>
                  <div className="list-meta">{item.meta}</div>
                </div>
              ))
            ) : (
              <p>No live stream events yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel recent-alerts-panel">
          <div className="panel-header">
            <h3>Recent Alerts</h3>
            <span>Latest correlated detections</span>
          </div>
          <div className="panel-list">
            {stats.recentAlerts.length > 0 ? (
              stats.recentAlerts.map((alert) => (
                <div
                  key={alert._id || `${alert.type}-${alert.timestamp}`}
                  className="list-row list-row-stack recent-alert-card"
                >
                  <div className="list-row__top">
                    <span>{alert.type || alert.attackType || "Threat"}</span>
                    <strong>{alert.severity || "Unknown"}</strong>
                  </div>
                  <div className="list-meta">
                    {titleCase(alert.source || "unknown")} •{" "}
                    {alert.ip || "Unknown IP"} • {formatTime(alert.timestamp)}
                  </div>
                </div>
              ))
            ) : (
              <p>No recent alerts yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Source IPs</h3>
            <span>Most active senders</span>
          </div>
          <div className="panel-list">
            {stats.topSourceIps.length > 0 ? (
              stats.topSourceIps.map((item, index) => (
                <div
                  key={`${item.name}-${index}`}
                  className="list-row list-row--pill"
                >
                  <span className="mono-text">{item.name}</span>
                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <p>No source IP data yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Destination IPs</h3>
            <span>Most targeted hosts</span>
          </div>
          <div className="panel-list">
            {stats.topDestinationIps.length > 0 ? (
              stats.topDestinationIps.map((item, index) => (
                <div
                  key={`${item.name}-${index}`}
                  className="list-row list-row--pill"
                >
                  <span className="mono-text">{item.name}</span>
                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <p>No destination IP data yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel panel-span-3">
          <div className="panel-header">
            <h3>Recent Telemetry</h3>
            <span>Latest events reaching the platform</span>
          </div>
          <div className="panel-table">
            {stats.recentLogs.length > 0 ? (
              <table>
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>Protocol</th>
                    <th>Classification</th>
                    <th>Priority</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Destination Port</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recentLogs.map((log, index) => (
                    <tr key={log._id || index}>
                      <td>{log.derivedMessage}</td>
                      <td>{log.derivedProtocol}</td>
                      <td>{log.derivedClassification}</td>
                      <td>{log.derivedPriority || "-"}</td>
                      <td className="mono-text">{log.derivedSrcIp}</td>
                      <td className="mono-text">{log.derivedDestIp}</td>
                      <td className="mono-text">{log.derivedDestPort}</td>
                      <td>{formatDateTime(log.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p>No telemetry has been stored yet.</p>
            )}
          </div>
        </div>
      </section>

      <div className="dashboard-actions">
        <button onClick={() => fetchStats()} className="refresh-btn">
          Refresh Dashboard
        </button>
      </div>
    </MainLayout>
  );
};

export default Dashboard;
