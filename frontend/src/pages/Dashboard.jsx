import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import MainLayout from "../layout/MainLayout";
import LiveTerminal from "../components/LiveTerminal";
import MetricCard from "../components/dashboard/MetricCard";
import StatusBadge from "../components/dashboard/StatusBadge";
import TableComponent from "../components/dashboard/TableComponent";
import useSocket from "../hooks/useSocket";
import { alerts, dashboard, logs } from "../services/api";
import "../styles/dashboard.css";

const SEVERITY_COLORS = {
  critical: "#ff5d73",
  high: "#ff9f43",
  medium: "#ffd166",
  low: "#4cd97b",
  info: "#4cc9f0",
  unknown: "#7c8aa5",
};

const CHART_COLORS = ["#35d6ff", "#2f7df6", "#7c3aed", "#f97316", "#facc15", "#10b981"];

const defaultDashboard = {
  mode: "waiting-for-telemetry",
  totalAlerts: 0,
  criticalSeverity: 0,
  highSeverity: 0,
  mediumSeverity: 0,
  lowSeverity: 0,
  recentLogs: [],
  recentAlerts: [],
  topAttackTypes: [],
  topSourceIps: [],
  topDestinationIps: [],
  timeline: [],
  traffic: {
    eventsLast24h: 0,
    hostEventsLast24h: 0,
    liveSnortEventsLast24h: 0,
    liveSnortAlertsLast24h: 0,
    hostAlertsLast24h: 0,
    mlAnomaliesLast24h: 0,
    uniqueSourceIps: 0,
    uniqueDestinationIps: 0,
    avgPriority: 0,
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
      hostname: "",
      queueDepth: 0,
    },
    stream: {
      mode: "memory",
      connected: false,
      lastPublishedAt: null,
    },
    lastDetectionTime: null,
    hostLastEventAt: null,
    snortLastEventAt: null,
    modelLoaded: null,
    usingFallback: null,
  },
  overview: {
    executive: {
      monitoredEndpoints: 0,
      onlineEndpoints: 0,
      alertsLast24h: 0,
      detectionsToday: 0,
      resolvedToday: 0,
      openIncidents: 0,
      telemetryEventsLast24h: 0,
      hostEventsLast24h: 0,
    },
    posture: {
      criticalAlerts: 0,
      highAlerts: 0,
      suspiciousCommands: 0,
      fileIntegrityChanges: 0,
      authenticationSignals: 0,
      sensorCoveragePercent: 0,
    },
    detections: {
      timeline: [],
      statusDistribution: [],
      topClassifications: [],
      topTalkers: [],
      topTargets: [],
    },
    endpoints: {
      riskTable: [],
      topHosts: [],
    },
    operations: {
      liveFeed: [],
    },
  },
  hostInsights: {
    activeHosts: 0,
    failedLoginCount: 0,
    suspiciousProcessCount: 0,
    fileChangeCount: 0,
    topHosts: [],
  },
};

const safeArray = (value) => (Array.isArray(value) ? value : []);

const safeStatus = (value) => {
  if (!value) return "unknown";
  return String(value).trim().toLowerCase();
};

const titleCase = (value) => {
  if (!value) return "Unknown";
  return String(value)
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
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

const shortenLabel = (value, maxLength = 24) => {
  const text = String(value || "");
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 3)}...`;
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
  if (source === "host" || source === "hids" || source === "agent" || source === "node-host-agent") {
    return "host";
  }

  const protocol = safeStatus(getProtocol(log));
  const message = safeStatus(getMessage(log));

  if (protocol === "unknown" && (message.includes("heartbeat") || message.includes("process"))) {
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

const buildBuckets = (items, keyGetter, limit = 8) => {
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

const getStatusTone = (value) => {
  const normalized = safeStatus(value);
  if (["online", "ok", "connected", "active", "healthy"].includes(normalized)) return "healthy";
  if (["offline", "error", "disconnected"].includes(normalized)) return "critical";
  return "warning";
};

const getSeverityTone = (value) => SEVERITY_COLORS[safeStatus(value)] || SEVERITY_COLORS.unknown;

const deriveModelLabel = (health) => {
  const idsStatus = safeStatus(health?.idsEngine);
  if (idsStatus === "offline") return "Unavailable";
  if (health?.modelLoaded === true) return health?.usingFallback ? "Fallback Model" : "Random Forest Loaded";
  if (health?.modelLoaded === false) return "Rules Only";
  return "Unknown";
};

const buildFeedItem = (label, meta, timestamp, severity = "info") => ({
  id: `${label}-${timestamp || Date.now()}`,
  label,
  meta,
  timestamp: timestamp || new Date().toISOString(),
  severity,
});

const Dashboard = () => {
  const [stats, setStats] = useState(defaultDashboard);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
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
      if (!silent) {
        setError("");
        setRefreshing(true);
      }

      const [overviewRes, statsRes, healthRes, alertsRes, logsRes] = await Promise.allSettled([
        dashboard.overview(),
        dashboard.stats(),
        dashboard.health(),
        alerts.list(120, 1),
        logs.list(150, 1),
      ]);

      const overviewData = overviewRes.status === "fulfilled" ? overviewRes.value?.data ?? {} : {};
      const statsData = statsRes.status === "fulfilled" ? statsRes.value?.data ?? {} : {};
      const healthData = healthRes.status === "fulfilled" ? healthRes.value?.data ?? {} : {};
      const alertsData = alertsRes.status === "fulfilled" ? safeArray(alertsRes.value?.data?.data) : [];
      const logData =
        logsRes.status === "fulfilled"
          ? safeArray(logsRes.value?.data?.data).map(deriveLog)
          : [];

      const recentLogs =
        safeArray(statsData?.analytics?.recentLogs).map(deriveLog).slice(0, 12) ||
        logData.slice(0, 12);

      const normalizedRecentLogs =
        recentLogs.length > 0 ? recentLogs : logData.slice(0, 12);

      const recentAlerts = safeArray(statsData?.analytics?.recentAlerts).length
        ? safeArray(statsData.analytics.recentAlerts).slice(0, 10)
        : alertsData.slice(0, 10);

      const hostLogs = logData.filter((log) => log.derivedSensorType === "host");
      const snortLogs = logData.filter((log) => log.derivedSensorType === "network");

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
          message.includes("encodedcommand") ||
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
        snort: safeStatus(healthData?.snort?.status ?? (snortLogs.length > 0 ? "online" : "unknown")),
        host: safeStatus(healthData?.host?.status ?? (hostLogs.length > 0 ? "online" : "unknown")),
        lastDetectionTime:
          healthData?.lastDetectionTime ??
          statsData?.lastDetectionTime ??
          recentAlerts?.[0]?.timestamp ??
          normalizedRecentLogs?.[0]?.timestamp ??
          null,
        hostLastEventAt: healthData?.host?.lastEventAt ?? hostLogs?.[0]?.timestamp ?? null,
        snortLastEventAt: healthData?.snort?.lastEventAt ?? snortLogs?.[0]?.timestamp ?? null,
        modelLoaded:
          healthData?.idsEngine?.modelLoaded === null || healthData?.idsEngine?.modelLoaded === undefined
            ? null
            : Boolean(healthData?.idsEngine?.modelLoaded),
        usingFallback:
          healthData?.idsEngine?.usingFallback === null || healthData?.idsEngine?.usingFallback === undefined
            ? null
            : Boolean(healthData?.idsEngine?.usingFallback),
        collector: {
          status: safeStatus(healthData?.collector?.status),
          lastHeartbeatAt: healthData?.collector?.lastHeartbeatAt || null,
          agentType: healthData?.collector?.agentType || null,
          hostname: healthData?.collector?.hostname || "",
          queueDepth: Number(healthData?.collector?.queueDepth || 0),
        },
        stream: {
          mode: healthData?.stream?.mode || "memory",
          connected: Boolean(healthData?.stream?.connected),
          lastPublishedAt: healthData?.stream?.lastPublishedAt || null,
        },
      };

      const nextState = {
        mode:
          statsData?.mode ||
          (normalizedRecentLogs.length > 0 || recentAlerts.length > 0 ? "live-monitoring" : "waiting-for-telemetry"),
        totalAlerts: statsData?.alerts?.total ?? overviewData?.executive?.alertsLast24h ?? alertsData.length,
        criticalSeverity:
          statsData?.alerts?.critical ?? overviewData?.posture?.criticalAlerts ?? 0,
        highSeverity: statsData?.alerts?.high ?? overviewData?.posture?.highAlerts ?? 0,
        mediumSeverity:
          statsData?.alerts?.medium ??
          alertsData.filter((item) => safeStatus(item?.severity) === "medium").length,
        lowSeverity:
          statsData?.alerts?.low ??
          alertsData.filter((item) => safeStatus(item?.severity) === "low").length,
        recentLogs: normalizedRecentLogs,
        recentAlerts,
        topAttackTypes: safeArray(statsData?.analytics?.topAttackTypes).length
          ? safeArray(statsData.analytics.topAttackTypes).slice(0, 8)
          : safeArray(overviewData?.detections?.topClassifications).slice(0, 8),
        topSourceIps: safeArray(statsData?.analytics?.topSourceIps).length
          ? safeArray(statsData.analytics.topSourceIps).slice(0, 8)
          : safeArray(overviewData?.detections?.topTalkers).slice(0, 8),
        topDestinationIps: safeArray(statsData?.analytics?.topDestinationIps).length
          ? safeArray(statsData.analytics.topDestinationIps).slice(0, 8)
          : safeArray(overviewData?.detections?.topTargets).slice(0, 8),
        timeline: safeArray(statsData?.analytics?.timeline).length
          ? safeArray(statsData.analytics.timeline)
          : safeArray(overviewData?.detections?.timeline),
        traffic: {
          eventsLast24h:
            statsData?.traffic?.eventsLast24h ?? overviewData?.executive?.telemetryEventsLast24h ?? logData.length,
          hostEventsLast24h:
            statsData?.traffic?.hostEventsLast24h ?? overviewData?.executive?.hostEventsLast24h ?? hostLogs.length,
          liveSnortEventsLast24h: statsData?.traffic?.liveSnortEventsLast24h ?? snortLogs.length,
          liveSnortAlertsLast24h:
            statsData?.traffic?.liveSnortAlertsLast24h ??
            alertsData.filter((alert) => safeStatus(alert.source) === "snort").length,
          hostAlertsLast24h: statsData?.traffic?.hostAlertsLast24h ?? 0,
          mlAnomaliesLast24h:
            statsData?.traffic?.mlAnomaliesLast24h ??
            logData.filter((log) => Boolean(log?.metadata?.idsEngine?.is_anomaly)).length,
          uniqueSourceIps: statsData?.traffic?.uniqueSourceIps ?? uniqueSourceIps,
          uniqueDestinationIps: statsData?.traffic?.uniqueDestinationIps ?? uniqueDestinationIps,
          avgPriority: statsData?.traffic?.avgPriority ?? avgPriority,
        },
        health: nextHealth,
        overview: {
          executive: {
            monitoredEndpoints: overviewData?.executive?.monitoredEndpoints ?? 0,
            onlineEndpoints: overviewData?.executive?.onlineEndpoints ?? activeHosts,
            alertsLast24h: overviewData?.executive?.alertsLast24h ?? alertsData.length,
            detectionsToday: overviewData?.executive?.detectionsToday ?? recentAlerts.length,
            resolvedToday: overviewData?.executive?.resolvedToday ?? 0,
            openIncidents:
              overviewData?.executive?.openIncidents ??
              recentAlerts.filter((alert) => safeStatus(alert?.status) !== "resolved").length,
            telemetryEventsLast24h: overviewData?.executive?.telemetryEventsLast24h ?? logData.length,
            hostEventsLast24h: overviewData?.executive?.hostEventsLast24h ?? hostLogs.length,
          },
          posture: overviewData?.posture ?? defaultDashboard.overview.posture,
          detections: {
            timeline: safeArray(overviewData?.detections?.timeline),
            statusDistribution: safeArray(overviewData?.detections?.statusDistribution),
            topClassifications: safeArray(overviewData?.detections?.topClassifications),
            topTalkers: safeArray(overviewData?.detections?.topTalkers),
            topTargets: safeArray(overviewData?.detections?.topTargets),
          },
          endpoints: {
            riskTable: safeArray(overviewData?.endpoints?.riskTable),
            topHosts: safeArray(overviewData?.endpoints?.topHosts),
          },
          operations: {
            liveFeed: safeArray(overviewData?.operations?.liveFeed),
          },
        },
        hostInsights: {
          activeHosts,
          failedLoginCount,
          suspiciousProcessCount,
          fileChangeCount,
          topHosts: safeArray(overviewData?.endpoints?.topHosts).length
            ? safeArray(overviewData.endpoints.topHosts)
            : buildBuckets(hostLogs, (log) => log.derivedHost, 6),
        },
      };

      const allRequestsFailed =
        overviewRes.status === "rejected" &&
        statsRes.status === "rejected" &&
        healthRes.status === "rejected" &&
        alertsRes.status === "rejected" &&
        logsRes.status === "rejected";

      if (isMountedRef.current) {
        setStats(nextState);
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
      if (isMountedRef.current) setRefreshing(false);
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
            buildFeedItem(
              "Socket session established",
              "Dashboard subscribed to the real-time telemetry channel",
              new Date().toISOString(),
              "info"
            ),
            ...current,
          ].slice(0, 12)
        );
      },
      "alerts:new": () => triggerRefresh(),
      "alerts:update": () => triggerRefresh(),
      "dashboard:update": () => triggerRefresh(),
      "log:new": (event) => {
        const newLog = event?.data || event;
        if (newLog) {
          setLiveLogs((current) => [deriveLog(newLog), ...current].slice(0, 50));
          setLiveOpsFeed((current) =>
            [
              buildFeedItem(
                "Telemetry event received",
                `${getMessage(newLog)} / ${titleCase(deriveSensorType(newLog))}`,
                newLog.timestamp || new Date().toISOString(),
                deriveSeverity(newLog)
              ),
              ...current,
            ].slice(0, 12)
          );

          setStats((current) => ({
            ...current,
            mode: "live-monitoring",
            recentLogs: [deriveLog(newLog), ...safeArray(current.recentLogs)].slice(0, 12),
            traffic: {
              ...current.traffic,
              eventsLast24h: Number(current.traffic.eventsLast24h || 0) + 1,
              hostEventsLast24h:
                deriveSensorType(newLog) === "host"
                  ? Number(current.traffic.hostEventsLast24h || 0) + 1
                  : current.traffic.hostEventsLast24h,
              liveSnortEventsLast24h:
                deriveSensorType(newLog) === "network"
                  ? Number(current.traffic.liveSnortEventsLast24h || 0) + 1
                  : current.traffic.liveSnortEventsLast24h,
            },
            health: {
              ...current.health,
              lastDetectionTime: newLog.timestamp || new Date().toISOString(),
              hostLastEventAt:
                deriveSensorType(newLog) === "host"
                  ? newLog.timestamp || new Date().toISOString()
                  : current.health.hostLastEventAt,
              snortLastEventAt:
                deriveSensorType(newLog) === "network"
                  ? newLog.timestamp || new Date().toISOString()
                  : current.health.snortLastEventAt,
            },
          }));
        }
        triggerRefresh();
      },
      "logs:new": (event) => {
        const newLog = event?.data || event;
        if (newLog) {
          setLiveLogs((current) => [deriveLog(newLog), ...current].slice(0, 50));
        }
        triggerRefresh();
      },
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
              hostname: heartbeat.hostname || current.health.collector.hostname,
              queueDepth: Number(heartbeat.queueDepth || 0),
            },
          },
        }));

        setLiveOpsFeed((current) =>
          [
            buildFeedItem(
              "Collector heartbeat",
              `${heartbeat.status || "unknown"} / ${heartbeat.agentType || "collector"} / queue ${heartbeat.queueDepth || 0}`,
              heartbeat.receivedAt || event?.timestamp || new Date().toISOString(),
              safeStatus(heartbeat.status) === "online" ? "low" : "medium"
            ),
            ...current,
          ].slice(0, 12)
        );
      },
      "stream:event": (event) => {
        setLiveOpsFeed((current) =>
          [
            buildFeedItem(
              event?.type || "Stream event",
              `${event?.source || "pipeline"} / inserted ${event?.insertedCount || 0} / duplicates ${event?.duplicateCount || 0}`,
              event?.timestamp || new Date().toISOString(),
              "info"
            ),
            ...current,
          ].slice(0, 12)
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

  const metricCards = useMemo(
    () => [
      {
        title: "Total Alerts (24h)",
        value: formatCompact(stats.totalAlerts),
        subtitle: "Detection volume across the platform",
        tone: "cyan",
      },
      {
        title: "Critical Alerts",
        value: formatCompact(stats.criticalSeverity),
        subtitle: "Immediate triage required",
        tone: "red",
      },
      {
        title: "Open Incidents",
        value: formatCompact(stats.overview.executive.openIncidents),
        subtitle: "Cases awaiting containment or closure",
        tone: "amber",
      },
      {
        title: "Logs (24h)",
        value: formatCompact(stats.traffic.eventsLast24h),
        subtitle: "Telemetry events ingested in the last day",
        tone: "blue",
      },
      {
        title: "Online Endpoints",
        value: formatCompact(stats.overview.executive.onlineEndpoints),
        subtitle: `${stats.overview.posture.sensorCoveragePercent || 0}% coverage across monitored assets`,
        tone: "green",
      },
    ],
    [stats]
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

  const attackTypeChartData = useMemo(
    () =>
      safeArray(stats.topAttackTypes).map((item) => ({
        ...item,
        name: shortenLabel(item.name, 22),
      })),
    [stats.topAttackTypes]
  );

  const timelineData = useMemo(() => safeArray(stats.timeline), [stats.timeline]);

  const realtimeRows = useMemo(() => {
    const liveFeedRows = safeArray(stats.overview.operations.liveFeed).map((item) => ({
      id: item.id || `${item.title}-${item.timestamp}`,
      time: formatTime(item.timestamp),
      event: item.title || "Telemetry Event",
      type: titleCase(item.classification || item.type || "Unknown"),
      source: item.host || item.source || "Unknown",
      severity: safeStatus(item.severity || "unknown"),
    }));

    const fallbackRows = safeArray(stats.recentLogs).map((log, index) => ({
      id: log._id || `${log.derivedMessage}-${index}`,
      time: formatTime(log.timestamp),
      event: log.derivedMessage,
      type: log.derivedClassification,
      source: log.derivedSensorType === "host" ? log.derivedHost : log.derivedSrcIp,
      severity: safeStatus(log.derivedSeverity),
    }));

    return (liveFeedRows.length > 0 ? liveFeedRows : fallbackRows).slice(0, 12);
  }, [stats.overview.operations.liveFeed, stats.recentLogs]);

  const threatCards = useMemo(
    () =>
      safeArray(stats.topAttackTypes).slice(0, 6).map((item) => ({
        ...item,
        name: shortenLabel(item.name, 26),
      })),
    [stats.topAttackTypes]
  );

  const sourceIps = useMemo(
    () => safeArray(stats.topSourceIps).slice(0, 6),
    [stats.topSourceIps]
  );

  const destinationIps = useMemo(
    () => safeArray(stats.topDestinationIps).slice(0, 6),
    [stats.topDestinationIps]
  );

  const endpointRows = useMemo(
    () => safeArray(stats.overview.endpoints.riskTable).slice(0, 8),
    [stats.overview.endpoints.riskTable]
  );

  const healthCards = useMemo(
    () => [
      {
        label: "Database",
        value: stats.health.database,
        meta: "Persistence and query layer",
      },
      {
        label: "IDS Engine",
        value: stats.health.idsEngine,
        meta: deriveModelLabel(stats.health),
      },
      {
        label: "Snort / NIDS",
        value: stats.health.snort,
        meta: stats.health.snortLastEventAt
          ? `Last event ${formatTime(stats.health.snortLastEventAt)}`
          : "Waiting for network telemetry",
      },
      {
        label: "Host Monitoring",
        value: stats.health.host,
        meta: stats.health.hostLastEventAt
          ? `Last event ${formatTime(stats.health.hostLastEventAt)}`
          : "Waiting for endpoint telemetry",
      },
    ],
    [stats]
  );

  const liveFeed = useMemo(
    () =>
      liveOpsFeed.length > 0
        ? liveOpsFeed
        : realtimeRows.slice(0, 6).map((row) =>
            buildFeedItem(row.event, `${row.type} / ${row.source}`, new Date().toISOString(), row.severity)
          ),
    [liveOpsFeed, realtimeRows]
  );

  const recentTerminalLogs = useMemo(
    () => (liveLogs.length > 0 ? liveLogs : stats.recentLogs.filter((log) => log.derivedSensorType === "host")),
    [liveLogs, stats.recentLogs]
  );

  const exportRowsAsCsv = useCallback((filename, rows) => {
    const safeRows = safeArray(rows);
    if (!safeRows.length) return;

    const headers = Object.keys(safeRows[0]);
    const escapeCell = (value) => {
      const text = value === null || value === undefined ? "" : String(value);
      return `"${text.replace(/"/g, '""')}"`;
    };

    const csv = [
      headers.join(","),
      ...safeRows.map((row) => headers.map((header) => escapeCell(row[header])).join(",")),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }, []);

  const exportLiveEvents = useCallback(() => {
    exportRowsAsCsv(
      `threatlens-live-events-${new Date().toISOString().slice(0, 10)}.csv`,
      realtimeRows.map((row) => ({
        time: row.time,
        event: row.event,
        type: row.type,
        source: row.source,
        severity: row.severity,
      }))
    );
  }, [exportRowsAsCsv, realtimeRows]);

  const exportEndpointRisk = useCallback(() => {
    exportRowsAsCsv(
      `threatlens-endpoint-risk-${new Date().toISOString().slice(0, 10)}.csv`,
      endpointRows.map((row) => ({
        hostname: row.hostname,
        status: row.status,
        riskScore: row.riskScore,
        openAlerts: row.openAlerts,
        lastSeenAt: formatDateTime(row.lastSeenAt),
      }))
    );
  }, [endpointRows, exportRowsAsCsv]);


  const realtimeColumns = useMemo(
    () => [
      { key: "time", title: "Time" },
      { key: "event", title: "Event" },
      { key: "type", title: "Type" },
      { key: "source", title: "Source" },
      {
        key: "severity",
        title: "Severity",
        render: (value) => <StatusBadge label={titleCase(value)} tone={getStatusTone(value)} compact />,
      },
    ],
    []
  );

  const endpointColumns = useMemo(
    () => [
      { key: "hostname", title: "Hostname" },
      {
        key: "status",
        title: "Status",
        render: (value) => <StatusBadge label={titleCase(value)} tone={getStatusTone(value)} compact pulse={safeStatus(value) === "online"} />,
      },
      {
        key: "riskScore",
        title: "Risk Score",
        render: (value) => <span className={`tl-soc-risk ${Number(value) >= 75 ? "high" : Number(value) >= 45 ? "medium" : "low"}`}>{value}</span>,
      },
      { key: "openAlerts", title: "Open Alerts" },
      {
        key: "lastSeenAt",
        title: "Last Seen",
        render: (value) => formatDateTime(value),
      },
    ],
    []
  );

  const healthTone = getStatusTone(
    stats.mode === "live-monitoring" && socketState.connectionStatus === "connected" ? "online" : socketState.connectionStatus
  );

  if (loading) {
    return (
      <MainLayout>
        <div className="tl-soc-loading">
          <div className="tl-soc-loading__ring" />
          <span>Bootstrapping ThreatLens SOC dashboard...</span>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="tl-soc-page">
        <section className="tl-soc-hero">
          <div className="tl-soc-hero__copy">
            <div className="tl-soc-kicker">ThreatLens / Hybrid IDS / Real-Time Security Monitoring</div>
            <h1>ThreatLens SOC Dashboard</h1>
            <p>
              Unified visibility across machine learning detections, host telemetry, network signals,
              endpoint risk, and analyst-facing live operations.
            </p>
            <div className="tl-soc-hero__meta">
              <StatusBadge
                label={stats.mode === "live-monitoring" ? "Live Monitoring Active" : "Waiting For Telemetry"}
                tone={healthTone}
                pulse={stats.mode === "live-monitoring"}
              />
              <span>Last updated: {lastUpdated ? formatDateTime(lastUpdated) : "Never"}</span>
              <span>Last detection: {formatTime(stats.health.lastDetectionTime)}</span>
              <span>Collector heartbeat: {formatTime(stats.health.collector.lastHeartbeatAt)}</span>
            </div>
          </div>

          <div className="tl-soc-hero__actions">
            <button type="button" className="tl-soc-refresh" onClick={() => fetchStats()} disabled={refreshing}>
              {refreshing ? "Refreshing..." : "Refresh Dashboard"}
            </button>
            <button type="button" className="tl-soc-refresh tl-soc-refresh--ghost" onClick={exportLiveEvents}>
              Export Live CSV
            </button>
            <div className="tl-soc-hero__signal">
              <span className="tl-soc-hero__signal-label">Socket</span>
              <strong>{titleCase(socketState.connectionStatus)}</strong>
              <small>{socketState.lastError || "Real-time subscription healthy"}</small>
            </div>
          </div>
        </section>

        {error ? <div className="error-message">{error}</div> : null}

        <section className="tl-soc-metrics">
          {metricCards.map((card) => (
            <MetricCard
              key={card.title}
              title={card.title}
              value={card.value}
              subtitle={card.subtitle}
              tone={card.tone}
            />
          ))}
        </section>

        <section className="tl-soc-grid tl-soc-grid--primary">
          <div className="tl-soc-panel tl-soc-panel--span-2">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Detection Timeline</span>
                <h3>Alerts Over Time</h3>
              </div>
              <StatusBadge label={`${formatCompact(stats.traffic.eventsLast24h)} events`} tone="cyan" compact />
            </div>
            <div className="tl-soc-chart">
              {timelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData} margin={{ top: 12, right: 16, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="tlSocTimelineGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#35d6ff" stopOpacity={0.65} />
                        <stop offset="95%" stopColor="#35d6ff" stopOpacity={0.04} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(148, 163, 184, 0.12)" vertical={false} />
                    <XAxis dataKey="time" stroke="#8ba0c7" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#8ba0c7" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="events"
                      stroke="#35d6ff"
                      strokeWidth={2.5}
                      fill="url(#tlSocTimelineGradient)"
                      name="Events"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="tl-soc-empty">No telemetry available yet.</div>
              )}
            </div>
          </div>

          <div className="tl-soc-panel">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Severity Breakdown</span>
                <h3>Severity Distribution</h3>
              </div>
            </div>
            <div className="tl-soc-chart">
              {severityChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityChartData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={62}
                      outerRadius={90}
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
                <div className="tl-soc-empty">No severity distribution available.</div>
              )}
            </div>
          </div>

          <div className="tl-soc-panel">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Threat Analytics</span>
                <h3>Top Attack Types</h3>
              </div>
            </div>
            <div className="tl-soc-chart">
              {attackTypeChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackTypeChartData} margin={{ top: 12, right: 8, left: 0, bottom: 8 }}>
                    <CartesianGrid stroke="rgba(148, 163, 184, 0.12)" vertical={false} />
                    <XAxis dataKey="name" stroke="#8ba0c7" tick={{ fontSize: 11 }} interval={0} angle={-18} textAnchor="end" height={60} />
                    <YAxis stroke="#8ba0c7" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                      {attackTypeChartData.map((entry, index) => (
                        <Cell key={entry.name} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="tl-soc-empty">No attack classifications available.</div>
              )}
            </div>
          </div>
        </section>

        <section className="tl-soc-grid tl-soc-grid--operations">
          <div className="tl-soc-panel tl-soc-panel--span-2">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Live Event Stream</span>
                <h3>Real-Time Feed</h3>
              </div>
              <StatusBadge label={`${realtimeRows.length} latest events`} tone="blue" compact />
            </div>
            <TableComponent
              columns={realtimeColumns}
              rows={realtimeRows}
              emptyText="No real-time telemetry events available."
              rowKey={(row) => row.id}
              rowClassName={(row) =>
                row.severity === "critical"
                  ? "tl-soc-table__row--critical"
                  : row.severity === "high"
                    ? "tl-soc-table__row--high"
                    : ""
              }
            />
          </div>

          <div className="tl-soc-panel">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Live Operations</span>
                <h3>Operations Feed</h3>
              </div>
            </div>
            <div className="tl-soc-feed">
              {liveFeed.length > 0 ? (
                liveFeed.map((item) => (
                  <div key={item.id} className={`tl-soc-feed__item severity-${safeStatus(item.severity)}`}>
                    <div className="tl-soc-feed__item-head">
                      <strong>{item.label}</strong>
                      <span>{formatTime(item.timestamp)}</span>
                    </div>
                    <div className="tl-soc-feed__item-meta">{item.meta}</div>
                  </div>
                ))
              ) : (
                <div className="tl-soc-empty">Waiting for live operations events.</div>
              )}
            </div>
          </div>
        </section>

        <section className="tl-soc-grid tl-soc-grid--intel">
          <div className="tl-soc-panel">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Threat Intelligence</span>
                <h3>Top Attack Types</h3>
              </div>
            </div>
            <div className="tl-soc-chip-grid">
              {threatCards.length > 0 ? (
                threatCards.map((item) => (
                  <div key={item.name} className="tl-soc-chip-card">
                    <span>{item.name}</span>
                    <strong>{item.value}</strong>
                  </div>
                ))
              ) : (
                <div className="tl-soc-empty">No attack type intelligence yet.</div>
              )}
            </div>
          </div>

          <div className="tl-soc-panel">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Top Source IPs</span>
                <h3>Most Active Senders</h3>
              </div>
            </div>
            <div className="tl-soc-list">
              {sourceIps.length > 0 ? (
                sourceIps.map((item) => (
                  <div key={item.name} className="tl-soc-list__row">
                    <span className="mono-text">{item.name}</span>
                    <strong>{item.value}</strong>
                  </div>
                ))
              ) : (
                <div className="tl-soc-empty">No source IP intelligence yet.</div>
              )}
            </div>
          </div>

          <div className="tl-soc-panel">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Top Target IPs</span>
                <h3>Most Targeted Hosts</h3>
              </div>
            </div>
            <div className="tl-soc-list">
              {destinationIps.length > 0 ? (
                destinationIps.map((item) => (
                  <div key={item.name} className="tl-soc-list__row">
                    <span className="mono-text">{item.name}</span>
                    <strong>{item.value}</strong>
                  </div>
                ))
              ) : (
                <div className="tl-soc-empty">No target IP intelligence yet.</div>
              )}
            </div>
          </div>
        </section>

        <section className="tl-soc-grid tl-soc-grid--risk">
          <div className="tl-soc-panel tl-soc-panel--span-2">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Endpoint Exposure</span>
                <h3>Endpoint Risk Table</h3>
              </div>
              <div className="tl-soc-panel__actions">
                <StatusBadge
                  label={`${formatCompact(stats.overview.executive.onlineEndpoints)} endpoints online`}
                  tone="green"
                  compact
                />
                <button type="button" className="tl-soc-mini-button" onClick={exportEndpointRisk}>
                  Export Risk CSV
                </button>
              </div>
            </div>
            <TableComponent
              columns={endpointColumns}
              rows={endpointRows}
              emptyText="No endpoint risk data available."
              rowKey={(row) => row.assetId || row.hostname}
              rowClassName={(row) => (Number(row.riskScore) >= 75 ? "tl-soc-table__row--critical" : "")}
            />
          </div>

          <div className="tl-soc-panel">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">System Health</span>
                <h3>Platform Status</h3>
              </div>
            </div>
            <div className="tl-soc-health-list">
              {healthCards.map((item) => (
                <div key={item.label} className="tl-soc-health-list__item">
                  <div>
                    <span>{item.label}</span>
                    <small>{item.meta}</small>
                  </div>
                  <StatusBadge label={titleCase(item.value)} tone={getStatusTone(item.value)} compact pulse={safeStatus(item.value) === "online"} />
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="tl-soc-grid tl-soc-grid--terminal">
          <div className="tl-soc-panel tl-soc-panel--span-3 tl-soc-panel--terminal">
            <div className="tl-soc-panel__header">
              <div>
                <span className="tl-soc-panel__eyebrow">Live Host Stream</span>
                <h3>Telemetry Terminal</h3>
              </div>
            </div>
            <LiveTerminal logs={recentTerminalLogs} />
          </div>
        </section>
      </div>
    </MainLayout>
  );
};

export default Dashboard;
