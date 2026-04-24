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
  Legend,
} from "recharts";

const SEVERITY_COLORS = {
  critical: "#ff5d73",
  high: "#ff9f43",
  medium: "#ffd166",
  low: "#4cd97b",
  info: "#4cc9f0",
  unknown: "#7c8aa5",
};

const CHART_COLORS = [
  "#48cae4",
  "#00b4d8",
  "#90e0ef",
  "#6ee7b7",
  "#ffd166",
  "#fb8500",
  "#c084fc",
  "#fb7185",
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
  alertSourceDistribution: [],
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
  }).format(Math.max(0, Number(value || 0)));

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
  return !normalized || normalized === "unknown" || normalized === "n/a" || normalized === "-";
};

const hasMeaningfulValue = (value) => !isUnknownLike(value);

const hasKnownPort = (value) => {
  const normalized = String(value || "").trim();
  return Boolean(normalized) && normalized !== "Unknown" && !normalized.startsWith("N/A");
};

const shortenLabel = (value, maxLength = 18) => {
  const text = String(value || "");
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 1)}…`;
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
  const processName = String(log?.processName || log?.metadata?.processName || "").toLowerCase();

  if (message.includes("file watch") || message.includes("file change")) return "File Integrity Change";
  if (message.includes("heartbeat")) return "System Heartbeat";
  if (message.includes("process") || processName) return "Process Activity";
  if (message.includes("auth") || message.includes("login")) return "Authentication Activity";
  if (message.includes("sql")) return "SQL Injection";
  if (message.includes("xss")) return "XSS Attempt";
  if (message.includes("brute")) return "Brute Force";
  if (message.includes("scan")) return "Recon / Scan";
  if (message.includes("flood") || message.includes("ddos") || message.includes("dos")) return "DoS / Flood";
  if (message.includes("trojan") || message.includes("malware")) return "Malware Activity";
  if (protocol.includes("icmp")) return "ICMP Activity";
  if (protocol.includes("udp")) return "UDP Activity";
  if (protocol.includes("tcp")) return "TCP Activity";

  return "General Threat";
};

const deriveSeverity = (log) => {
  const raw = String(
    log?.severity ||
      log?.metadata?.severity ||
      log?.metadata?.snort?.severity ||
      log?.metadata?.snort?.priority ||
      ""
  ).toLowerCase();

  if (["critical", "high", "medium", "low", "info"].includes(raw)) return raw;

  const message = getMessage(log).toLowerCase();
  const processName = String(log?.processName || log?.metadata?.processName || "").toLowerCase();

  if (
    message.includes("encodedcommand") ||
    message.includes("powershell") ||
    message.includes("wmic") ||
    processName.includes("powershell") ||
    processName.includes("wmic")
  ) {
    return "high";
  }

  if (message.includes("file watch") || message.includes("file change")) return "medium";
  if (message.includes("heartbeat")) return "info";
  if (message.includes("process")) return "low";

  return "unknown";
};

const deriveSensorType = (log) => {
  const source = safeStatus(log?.metadata?.sensorType || log?.source);

  if (source === "snort" || source === "suricata") return "network";
  if (source === "host" || source === "hids" || source === "agent" || source === "node-host-agent") return "host";

  const protocol = safeStatus(getProtocol(log));
  const message = safeStatus(getMessage(log));

  if (protocol === "unknown" && (message.includes("heartbeat") || message.includes("process") || message.includes("file watch"))) {
    return "host";
  }

  return source === "unknown" ? "host" : source;
};

const deriveHost = (log) =>
  log?.hostname ||
  log?.host ||
  log?.metadata?.hostname ||
  log?.metadata?.host ||
  log?.asset_id ||
  log?.assetId ||
  "Unknown Host";

const deriveLog = (log) => ({
  ...log,
  derivedMessage: getMessage(log),
  derivedProtocol: getProtocol(log),
  derivedDestPort: getDestPort(log),
  derivedSrcIp: getSrcIp(log),
  derivedDestIp: getDestIp(log),
  derivedPriority: getPriority(log),
  derivedClassification: deriveClassification(log),
  derivedSeverity: deriveSeverity(log),
  derivedSensorType: deriveSensorType(log),
  derivedHost: deriveHost(log),
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

const isNetworkTelemetryLog = (log) => log?.derivedSensorType === "network";

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
  if (health?.modelLoaded === true) return health?.usingFallback ? "Fallback Model" : "Random Forest Loaded";
  if (health?.modelLoaded === false) return "Rules Only";
  return "Unknown";
};

const getStatusTone = (value) => {
  const normalized = safeStatus(value);
  if (normalized === "online" || normalized === "ok" || normalized === "connected" || normalized === "active") {
    return "healthy";
  }
  if (normalized === "offline" || normalized === "disconnected") {
    return "offline";
  }
  return "degraded";
};

const getSeverityTone = (value) => {
  const normalized = safeStatus(value);
  return SEVERITY_COLORS[normalized] || SEVERITY_COLORS.unknown;
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

      const [alertsRes, logsRes, statsRes, healthRes] = await Promise.allSettled([
        alerts.list(100, 1),
        logs.list(120, 1),
        dashboard.stats(),
        dashboard.health(),
      ]);

      const alertsData =
        alertsRes.status === "fulfilled" ? safeArray(alertsRes.value?.data?.data) : [];

      const logData =
        logsRes.status === "fulfilled"
          ? safeArray(logsRes.value?.data?.data).map(deriveLog)
          : [];

      const statsData = statsRes.status === "fulfilled" ? statsRes.value?.data ?? {} : {};
      const healthData = healthRes.status === "fulfilled" ? healthRes.value?.data ?? {} : {};

      const apiRecentLogs = safeArray(statsData?.analytics?.recentLogs).map(deriveLog);
      const recentLogs = apiRecentLogs.length > 0 ? apiRecentLogs.slice(0, 12) : logData.slice(0, 12);
      const recentAlerts = safeArray(statsData?.analytics?.recentAlerts).length
        ? safeArray(statsData?.analytics?.recentAlerts).slice(0, 8)
        : alertsData.slice(0, 8);

      const snortLogs = logData.filter(isNetworkTelemetryLog);
      const hostLogs = logData.filter((log) => log.derivedSensorType === "host");
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
        (item) => item?.attackType || item?.type || item?.title,
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
        alertsData.length
          ? alertsData.map((item) => ({ ...item, severity: item?.severity || "unknown" }))
          : hostLogs,
        (item) => item?.severity || item?.derivedSeverity || "unknown",
        6
      );

      const fallbackHostActivity = buildBuckets(
        hostLogs,
        (log) => log.derivedClassification,
        6
      );

      const fallbackTopHosts = buildBuckets(
        hostLogs,
        (log) => log.derivedHost,
        6
      );

      const uniqueSourceIps = new Set(
        logData.map((log) => log.derivedSrcIp).filter((value) => !isUnknownLike(value))
      ).size;

      const uniqueDestinationIps = new Set(
        logData.map((log) => log.derivedDestIp).filter((value) => !isUnknownLike(value))
      ).size;

      const avgPriority =
        logData.length > 0
          ? logData.reduce((sum, log) => sum + log.derivedPriority, 0) / logData.length
          : 0;

      const failedLoginCount = hostLogs.filter((log) =>
        log.derivedClassification.toLowerCase().includes("authentication")
      ).length;

      const suspiciousProcessCount = hostLogs.filter((log) => {
        const message = String(log.derivedMessage || "").toLowerCase();
        return (
          message.includes("powershell") ||
          message.includes("wmic") ||
          message.includes("cmd") ||
          log.derivedClassification.toLowerCase().includes("process")
        );
      }).length;

      const fileChangeCount = hostLogs.filter((log) =>
        log.derivedClassification.toLowerCase().includes("file")
      ).length;

      const activeHosts = new Set(
        hostLogs.map((log) => log.derivedHost).filter((host) => !isUnknownLike(host))
      ).size;

      const nextHealth = {
        database: safeStatus(healthData?.database),
        idsEngine: safeStatus(healthData?.idsEngine?.status ?? healthData?.idsEngine),
        snort: safeStatus(
          healthData?.snort?.status ?? (snortLogs.length > 0 ? "online" : "unknown")
        ),
        host: safeStatus(
          healthData?.host?.status ??
            (hostLogs.length > 0 ? "online" : "unknown")
        ),
        lastDetectionTime:
          healthData?.lastDetectionTime ??
          recentAlerts?.[0]?.timestamp ??
          recentLogs?.[0]?.timestamp ??
          null,
        liveSnortEventsLast24h:
          healthData?.snort?.liveEventsLast24h ?? snortLogs.length,
        liveHostEventsLast24h:
          healthData?.host?.liveEventsLast24h ?? hostLogs.length,
        snortLastEventAt:
          healthData?.snort?.lastEventAt ?? snortLogs?.[0]?.timestamp ?? null,
        hostLastEventAt:
          healthData?.host?.lastEventAt ?? hostLogs?.[0]?.timestamp ?? null,
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
        alertsData.filter((item) => safeStatus(item?.severity) === safeStatus(level)).length;

      const allRequestsFailed =
        alertsRes.status === "rejected" &&
        logsRes.status === "rejected" &&
        statsRes.status === "rejected" &&
        healthRes.status === "rejected";

      const nextStats = {
        mode:
          statsData?.mode ||
          (logData.length > 0 || alertsData.length > 0 ? "live-monitoring" : "waiting-for-telemetry"),
        totalAlerts: statsData?.alerts?.total ?? alertsData.length,
        criticalSeverity: statsData?.alerts?.critical ?? severityCount("critical"),
        highSeverity: statsData?.alerts?.high ?? severityCount("high"),
        mediumSeverity: statsData?.alerts?.medium ?? severityCount("medium"),
        lowSeverity: statsData?.alerts?.low ?? severityCount("low"),
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
        protocolDistribution: safeArray(statsData?.analytics?.protocolDistribution).length
          ? safeArray(statsData?.analytics?.protocolDistribution)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackProtocolDistribution,
        alertSourceDistribution: safeArray(statsData?.analytics?.alertSourceDistribution).length
          ? safeArray(statsData?.analytics?.alertSourceDistribution)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackAlertSourceDistribution,
        severityDistribution: safeArray(statsData?.analytics?.severityDistribution).length
          ? safeArray(statsData?.analytics?.severityDistribution).slice(0, 6)
          : fallbackSeverityDistribution,
        topSourceIps: safeArray(statsData?.analytics?.topSourceIps).length
          ? safeArray(statsData?.analytics?.topSourceIps)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackTopSourceIps,
        topDestinationIps: safeArray(statsData?.analytics?.topDestinationIps).length
          ? safeArray(statsData?.analytics?.topDestinationIps)
              .filter((item) => !isUnknownLike(item?.name))
              .slice(0, 6)
          : fallbackTopDestinationIps,
        timeline: safeArray(statsData?.analytics?.timeline),
        hostInsights: {
          failedLoginCount,
          suspiciousProcessCount,
          fileChangeCount,
          activeHosts,
          topHosts: fallbackTopHosts,
          hostActivityMix: fallbackHostActivity,
        },
        traffic: {
          eventsLast24h: statsData?.traffic?.eventsLast24h ?? logData.length,
          uniqueSourceIps: statsData?.traffic?.uniqueSourceIps ?? uniqueSourceIps,
          uniqueDestinationIps:
            statsData?.traffic?.uniqueDestinationIps ?? uniqueDestinationIps,
          avgPriority: statsData?.traffic?.avgPriority ?? avgPriority,
          liveSnortEventsLast24h:
            statsData?.traffic?.liveSnortEventsLast24h ?? snortLogs.length,
          hostEventsLast24h:
            statsData?.traffic?.hostEventsLast24h ?? hostLogs.length,
          liveSnortAlertsLast24h:
            statsData?.traffic?.liveSnortAlertsLast24h ??
            alertsData.filter((alert) => safeStatus(alert.source) === "snort").length,
          hostAlertsLast24h: statsData?.traffic?.hostAlertsLast24h ?? 0,
          mlAnomaliesLast24h:
            statsData?.traffic?.mlAnomaliesLast24h ??
            logData.filter((log) => Boolean(log?.metadata?.idsEngine?.is_anomaly)).length,
          telemetryCoverage: statsData?.traffic?.telemetryCoverage ?? {
            total: logData.length,
            withProtocol: logData.filter((log) => hasMeaningfulValue(log.derivedProtocol)).length,
            withDestination: logData.filter((log) => hasMeaningfulValue(log.derivedDestIp)).length,
            withPort: logData.filter((log) => hasKnownPort(log.derivedDestPort)).length,
            unknownProtocol: logData.filter((log) => !hasMeaningfulValue(log.derivedProtocol)).length,
            unknownDestination: logData.filter((log) => !hasMeaningfulValue(log.derivedDestIp)).length,
            unknownPort: logData.filter((log) => !hasKnownPort(log.derivedDestPort)).length,
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
    if (now - lastRefreshRequestRef.current < 1500) return;
    lastRefreshRequestRef.current = now;

    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      fetchStats(true);
    }, 300);
  }, [fetchStats]);

  const socketHandlers = useMemo(
    () => ({
      "socket:ready": () => {
        setLiveOpsFeed((current) =>
          [
            {
              id: `socket-ready-${Date.now()}`,
              label: "Socket session established",
              meta: "Dashboard subscribed to the real-time channel",
              timestamp: new Date().toISOString(),
            },
            ...current,
          ].slice(0, 10)
        );
      },
      "alerts:new": triggerRefresh,
      "alerts:update": triggerRefresh,
      "log:new": (event) => {
        const newLog = event?.data || event;
        if (newLog) {
          setLiveLogs((current) => [deriveLog(newLog), ...current].slice(0, 50));
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

        setLiveOpsFeed((current) =>
          [
            {
              id: `heartbeat-${event?.timestamp || Date.now()}`,
              label: "Collector heartbeat",
              meta: `${heartbeat.status || "unknown"} / ${heartbeat.agentType || "collector"} / queue ${heartbeat.queueDepth || 0}`,
              timestamp: heartbeat.receivedAt || event?.timestamp || new Date().toISOString(),
            },
            ...current,
          ].slice(0, 10)
        );
      },
      "stream:event": (event) => {
        setLiveOpsFeed((current) =>
          [
            {
              id: `${event?.type || "stream"}-${event?.timestamp || Date.now()}`,
              label: event?.type || "Stream event",
              meta: `${event?.source || "pipeline"} / inserted ${event?.insertedCount || 0} / duplicates ${event?.duplicateCount || 0}`,
              timestamp: event?.timestamp || new Date().toISOString(),
            },
            ...current,
          ].slice(0, 10)
        );
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
      if (document.visibilityState === "visible" && socketState.connectionStatus !== "connected") {
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
        note: "Detection volume",
      },
      {
        label: "Events 24h",
        value: formatCompact(stats.traffic.eventsLast24h),
        note: "Total telemetry observed",
      },
      {
        label: "Host Events",
        value: formatCompact(stats.traffic.hostEventsLast24h),
        note: "HIDS telemetry",
      },
      {
        label: "Active Hosts",
        value: formatCompact(stats.hostInsights?.activeHosts || 0),
        note: "Endpoints reporting in",
      },
      {
        label: "Suspicious Processes",
        value: formatCompact(stats.hostInsights?.suspiciousProcessCount || 0),
        note: "Process activity to review",
      },
      {
        label: "File Changes",
        value: formatCompact(stats.hostInsights?.fileChangeCount || 0),
        note: "Integrity-related events",
      },
      {
        label: "Failed Logins",
        value: formatCompact(stats.hostInsights?.failedLoginCount || 0),
        note: "Authentication activity",
      },
      {
        label: "ML Anomalies",
        value: formatCompact(stats.traffic.mlAnomaliesLast24h),
        note: "Model-flagged events",
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
        label: "Host Alerts 24h",
        value: formatCompact(stats.traffic.hostAlertsLast24h),
        note:
          stats.traffic.hostAlertsLast24h > 0
            ? "Endpoint detections generated"
            : stats.traffic.hostEventsLast24h > 0
              ? "HIDS active, no high severity detections yet"
              : "Waiting for host detections",
      },
      {
        label: "Model State",
        value: deriveModelLabel(stats.health),
        note: "Detection engine readiness",
      },
    ],
    [stats]
  );

  const hostHealthCards = useMemo(
    () => [
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
        label: "Database",
        value: titleCase(stats.health.database),
        meta: "Telemetry persistence layer",
        tone: getStatusTone(stats.health.database),
      },
      {
        label: "IDS Engine",
        value: titleCase(stats.health.idsEngine),
        meta: deriveModelLabel(stats.health),
        tone: getStatusTone(stats.health.idsEngine),
      },
      {
        label: "Event Stream",
        value: stats.health.stream.connected ? titleCase(stats.health.stream.mode) : "Fallback",
        meta: stats.health.stream.lastPublishedAt
          ? `Last publish ${formatTime(stats.health.stream.lastPublishedAt)}`
          : "Waiting for stream events",
        tone: stats.health.stream.connected ? "healthy" : "degraded",
      },
    ],
    [socketState.connectionStatus, socketState.lastError, stats]
  );

  const severityChartData = useMemo(
    () => [
      { name: "Critical", value: stats.criticalSeverity },
      { name: "High", value: stats.highSeverity },
      { name: "Medium", value: stats.mediumSeverity },
      { name: "Low", value: stats.lowSeverity },
    ].filter((item) => item.value > 0),
    [stats]
  );

  const hostActivityMix = useMemo(
    () =>
      safeArray(stats.hostInsights?.hostActivityMix).map((item) => ({
        ...item,
        name: shortenLabel(item.name, 18),
      })),
    [stats]
  );

  const topHosts = useMemo(
    () =>
      safeArray(stats.hostInsights?.topHosts).map((item) => ({
        ...item,
        name: shortenLabel(item.name, 18),
      })),
    [stats]
  );

  const recentHostLogs = useMemo(
    () =>
      stats.recentLogs
        .filter((log) => log.derivedSensorType === "host")
        .slice(0, 8),
    [stats.recentLogs]
  );

  const showNetworkPanels = stats.traffic.networkCoverage.total > 0 || stats.protocolDistribution.length > 0;
  const healthTone = getStatusTone(stats.health.host);

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
          <div className="command-eyebrow">ThreatLens / HIDS / Real-Time Host Operations</div>
          <h1>Threat Operations Dashboard</h1>
          <p>
            Live visibility across host telemetry, endpoint health, real-time detections, and platform readiness.
          </p>
          <div className="dashboard-hero__meta">
            <span>Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "Never"}</span>
            <span>Last detection: {formatTime(stats.health.lastDetectionTime)}</span>
            <span>Last heartbeat: {formatTime(stats.health.collector.lastHeartbeatAt)}</span>
            <span>Last host event: {formatTime(stats.health.hostLastEventAt)}</span>
          </div>
        </div>

        <div className={`status-pill ${healthTone}`}>
          <span className="status-dot" />
          {stats.mode === "live-monitoring" ? "Live monitoring active" : "Waiting for telemetry"}
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
        {hostHealthCards.map((card) => (
          <div key={card.label} className={`ops-card ops-card--${card.tone}`}>
            <span className="ops-card__label">{card.label}</span>
            <strong>{card.value}</strong>
            <small>{card.meta}</small>
          </div>
        ))}
      </section>

      <section className="severity-strip">
        <div className="dashboard-panel severity-chart-panel">
          <div className="panel-header">
            <h3>Alert Severity Mix</h3>
            <span>Live detection distribution</span>
          </div>
          <div className="panel-chart panel-chart--sm">
            {severityChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityChartData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={56}
                    outerRadius={86}
                    paddingAngle={4}
                  >
                    {severityChartData.map((entry) => (
                      <Cell key={entry.name} fill={getSeverityTone(entry.name)} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state">No alerts yet</div>
            )}
          </div>
        </div>

        {overviewMetrics.map((item) => (
          <div key={item.label} className="severity-panel metric-emphasis">
            <div className="severity-head">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
            <small>{item.note}</small>
          </div>
        ))}
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
                <AreaChart data={stats.timeline} margin={{ top: 12, right: 16, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="eventsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#48cae4" stopOpacity={0.85} />
                      <stop offset="95%" stopColor="#48cae4" stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
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
            <h3>Host Activity Mix</h3>
            <span>Most common host behaviors</span>
          </div>
          <div className="panel-chart">
            {hostActivityMix.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={hostActivityMix} layout="vertical" margin={{ top: 8, right: 12, left: 12, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis type="number" stroke="#93a4c3" allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#93a4c3" width={140} tick={{ fontSize: 11 }} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#7dd3fc" radius={[0, 10, 10, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p>No host activity telemetry yet.</p>
            )}
          </div>
        </div>

        <div className="panel-span-2">
          <LiveTerminal logs={liveLogs.length ? liveLogs : recentHostLogs} />
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Live Operations Feed</h3>
            <span>Socket and ingestion activity</span>
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

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>Top Hosts</h3>
            <span>Most active monitored endpoints</span>
          </div>
          <div className="panel-list">
            {topHosts.length > 0 ? (
              topHosts.map((item, index) => (
                <div key={`${item.name}-${index}`} className="list-row list-row--pill">
                  <span>{item.name}</span>
                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <p>No host distribution data yet.</p>
            )}
          </div>
        </div>

        <div className="dashboard-panel">
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
                    <span>{alert.type || alert.attackType || alert.title || "Threat"}</span>
                    <strong
                      style={{
                        color: getSeverityTone(alert.severity || "unknown"),
                      }}
                    >
                      {titleCase(alert.severity || "unknown")}
                    </strong>
                  </div>
                  <div className="list-meta">
                    {titleCase(alert.source || "unknown")} • {alert.ip || "Unknown IP"} • {formatTime(alert.timestamp)}
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
            <h3>Recent Host Telemetry</h3>
            <span>Latest endpoint events</span>
          </div>
          <div className="panel-list">
            {recentHostLogs.length > 0 ? (
              recentHostLogs.map((log, index) => (
                <div key={log._id || index} className="list-row list-row-stack recent-alert-card">
                  <div className="list-row__top">
                    <span>{shortenLabel(log.derivedMessage, 34)}</span>
                    <strong style={{ color: getSeverityTone(log.derivedSeverity) }}>
                      {titleCase(log.derivedSeverity)}
                    </strong>
                  </div>
                  <div className="list-meta">
                    {log.derivedClassification} • {log.derivedHost} • {formatTime(log.timestamp)}
                  </div>
                </div>
              ))
            ) : (
              <p>No host telemetry yet.</p>
            )}
          </div>
        </div>

        {showNetworkPanels && (
          <>
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
                          <Cell key={`${entry.name}-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
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
                  : "NIDS is not active yet."}
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
                    <div key={`${item.name}-${index}`} className="list-row list-row--pill">
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
                    <div key={`${item.name}-${index}`} className="list-row list-row--pill">
                      <span className="mono-text">{item.name}</span>
                      <strong>{item.value}</strong>
                    </div>
                  ))
                ) : (
                  <p>No destination IP data yet.</p>
                )}
              </div>
            </div>
          </>
        )}

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
                    <th>Type</th>
                    <th>Classification</th>
                    <th>Severity</th>
                    <th>Host / Source</th>
                    <th>Protocol</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recentLogs.map((log, index) => (
                    <tr key={log._id || index}>
                      <td>{log.derivedMessage}</td>
                      <td>{titleCase(log.derivedSensorType)}</td>
                      <td>{log.derivedClassification}</td>
                      <td>
                        <span
                          className="severity-badge"
                          style={{ background: `${getSeverityTone(log.derivedSeverity)}22`, color: getSeverityTone(log.derivedSeverity), borderColor: `${getSeverityTone(log.derivedSeverity)}55` }}
                        >
                          {titleCase(log.derivedSeverity)}
                        </span>
                      </td>
                      <td className="mono-text">
                        {log.derivedSensorType === "host" ? log.derivedHost : log.derivedSrcIp}
                      </td>
                      <td>{log.derivedProtocol}</td>
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