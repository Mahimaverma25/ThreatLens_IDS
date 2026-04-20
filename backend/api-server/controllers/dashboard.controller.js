const mongoose = require("mongoose");

const Alert = require("../models/Alerts");
const Asset = require("../models/Asset");
const Log = require("../models/Log");
const { getIdsEngineHealth } = require("../services/detection.service");

const TIME_WINDOW_HOURS = 24;
const LIVE_STATUS_WINDOW_MINS = 5;
const AGENT_STATUS_WINDOW_MINS = 30;
const DETECTION_ALERT_SOURCES = ["snort", "rule-engine", "ids-engine-ml", "ids-engine"];

const buildSnortLogMatch = () => ({
  $or: [{ source: "snort" }, { "metadata.snort": { $exists: true, $ne: null } }]
});

const buildTelemetryLogMatch = () => ({
  $or: [
    { source: "snort" },
    { source: "agent" },
    { source: "ids-engine" },
    { source: "rule-engine" },
    { source: "ids-engine-ml" },
    { eventType: "snort.alert" },
    { "metadata.snort": { $exists: true, $ne: null } },
    { "metadata.idsEngine": { $exists: true, $ne: null } }
  ]
});

const normalizeText = (value) => {
  if (value === null || value === undefined) return "";
  return String(value).trim();
};

const isUnknownLike = (value) => {
  const normalized = normalizeText(value).toLowerCase();
  return !normalized || normalized === "unknown" || normalized === "n/a" || normalized === "-";
};

const titleCase = (value) => {
  const normalized = normalizeText(value);
  if (!normalized) return "Unknown";

  return normalized
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
};

const getProtocol = (log) => {
  return (
    log?.metadata?.protocol ||
    log?.metadata?.appProtocol ||
    log?.metadata?.snort?.protocol ||
    log?.protocol ||
    "Unknown"
  );
};

const getMessage = (log) => {
  return (
    log?.metadata?.snort?.message ||
    log?.message ||
    log?.signature ||
    "Unknown Event"
  );
};

const getSrcIp = (log) => {
  return (
    log?.metadata?.snort?.srcIp ||
    log?.ip ||
    log?.metadata?.sourceIp ||
    log?.sourceIp ||
    "Unknown"
  );
};

const getDestIp = (log) => {
  return (
    log?.metadata?.snort?.destIp ||
    log?.metadata?.destinationIp ||
    log?.destinationIp ||
    "Unknown"
  );
};

const getDestPort = (log) => {
  const protocol = String(getProtocol(log)).toUpperCase();

  const rawPort =
    log?.metadata?.snort?.destPort ??
    log?.metadata?.destinationPort ??
    log?.metadata?.port ??
    log?.destPort ??
    log?.destinationPort ??
    null;

  if (rawPort !== null && rawPort !== undefined && String(rawPort).trim() !== "") {
    const value = String(rawPort).trim();
    if (!isUnknownLike(value)) return value;
  }

  if (protocol.includes("ICMP")) {
    return "N/A (ICMP)";
  }

  return "Unknown";
};

const getPriority = (log) => {
  const raw =
    log?.metadata?.snort?.priority ??
    log?.priority ??
    log?.severityScore ??
    0;

  const num = Number(raw);
  return Number.isNaN(num) ? 0 : num;
};

const deriveClassification = (log) => {
  const explicit =
    log?.metadata?.snort?.classification ||
    log?.classification ||
    log?.metadata?.classification;

  if (!isUnknownLike(explicit)) {
    return titleCase(explicit);
  }

  const message = getMessage(log).toLowerCase();
  const protocol = String(getProtocol(log)).toLowerCase();

  if (message.includes("icmp")) return "ICMP Activity";
  if (message.includes("sql")) return "SQL Injection";
  if (message.includes("xss")) return "XSS Attempt";
  if (message.includes("brute") || message.includes("login")) return "Brute Force";
  if (message.includes("scan") || message.includes("portscan") || message.includes("port scan")) {
    return "Port Scan";
  }
  if (message.includes("flood") || message.includes("ddos") || message.includes("dos")) {
    return "DoS / Flood";
  }
  if (protocol.includes("icmp")) return "ICMP Activity";
  if (protocol.includes("tcp")) return "TCP Activity";
  if (protocol.includes("udp")) return "UDP Activity";

  return "General Threat";
};

const normalizeLog = (log) => ({
  ...log.toObject?.() ? log.toObject() : log,
  derived: {
    message: getMessage(log),
    protocol: getProtocol(log),
    classification: deriveClassification(log),
    srcIp: getSrcIp(log),
    destIp: getDestIp(log),
    destPort: getDestPort(log),
    priority: getPriority(log)
  }
});

const groupCounts = (items, accessor, limit = 6) => {
  const counts = items.reduce((accumulator, item) => {
    const rawKey = accessor(item);
    const key = !isUnknownLike(rawKey) ? String(rawKey).trim() : "Unknown";
    accumulator[key] = (accumulator[key] || 0) + 1;
    return accumulator;
  }, {});

  return Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, limit);
};

const hasDerivedProtocol = (log) => !isUnknownLike(log?.derived?.protocol);
const hasDerivedDestIp = (log) => !isUnknownLike(log?.derived?.destIp);
const hasDerivedSrcIp = (log) => !isUnknownLike(log?.derived?.srcIp);
const hasDerivedPort = (log) => {
  const value = String(log?.derived?.destPort || "").trim();
  return value && value !== "Unknown" && !value.startsWith("N/A");
};

const buildTelemetryCoverage = (logs) => {
  const total = logs.length;
  const withProtocol = logs.filter(hasDerivedProtocol).length;
  const withDestination = logs.filter(hasDerivedDestIp).length;
  const withPort = logs.filter(hasDerivedPort).length;

  return {
    total,
    withProtocol,
    withDestination,
    withPort,
    unknownProtocol: Math.max(0, total - withProtocol),
    unknownDestination: Math.max(0, total - withDestination),
    unknownPort: Math.max(0, total - withPort)
  };
};

const averageMetric = (logs, accessor) => {
  if (!logs.length) return 0;

  const total = logs.reduce((sum, log) => sum + Number(accessor(log) || 0), 0);
  return Number((total / logs.length).toFixed(2));
};

const buildTimelineBuckets = (logs) => {
  const buckets = new Map();
  const now = Date.now();

  for (let index = TIME_WINDOW_HOURS - 1; index >= 0; index -= 1) {
    const date = new Date(now - index * 60 * 60 * 1000);
    const key = `${String(date.getHours()).padStart(2, "0")}:00`;

    buckets.set(key, {
      time: key,
      events: 0,
      priorityScore: 0,
      criticalEvents: 0,
      highEvents: 0,
      anomalies: 0
    });
  }

  logs.forEach((log) => {
    if (!log.timestamp) return;

    const date = new Date(log.timestamp);
    if (Number.isNaN(date.getTime())) return;

    const key = `${String(date.getHours()).padStart(2, "0")}:00`;
    if (!buckets.has(key)) return;

    const bucket = buckets.get(key);
    const priority = getPriority(log);
    const severity = normalizeText(log?.severity).toLowerCase();
    const isAnomaly = Boolean(log?.metadata?.idsEngine?.is_anomaly);

    bucket.events += 1;
    bucket.priorityScore += priority;

    if (severity === "critical" || priority === 1) {
      bucket.criticalEvents += 1;
    }

    if (severity === "high" || priority === 2) {
      bucket.highEvents += 1;
    }

    if (isAnomaly) {
      bucket.anomalies += 1;
    }
  });

  return [...buckets.values()];
};

const normalizeIdsEngineHealth = (idsEngine) => {
  const raw = idsEngine || {};
  const status = normalizeText(raw?.status || raw?.state || raw?.health || raw);

  return {
    status: status ? status.toLowerCase() : "unknown",
    modelLoaded:
      raw?.modelLoaded ??
      raw?.model_loaded ??
      raw?.isModelLoaded ??
      null,
    usingFallback:
      raw?.usingFallback ??
      raw?.using_fallback ??
      raw?.fallback ??
      null,
    version: raw?.version || null,
    message: raw?.message || null
  };
};

const getStats = async (req, res) => {
  try {
    const orgFilter = { _org_id: req.orgId };
    const recentWindow = {
      $gte: new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000)
    };

    const liveSnortFilter = {
      ...orgFilter,
      ...buildSnortLogMatch()
    };

    const telemetryLogFilter = {
      ...orgFilter,
      ...buildTelemetryLogMatch()
    };

    const alertFilter = {
      ...orgFilter,
      source: { $in: DETECTION_ALERT_SOURCES }
    };

    const recentSnortFilter = {
      ...liveSnortFilter,
      timestamp: recentWindow
    };

    const recentTelemetryFilter = {
      ...telemetryLogFilter,
      timestamp: recentWindow
    };

    const recentAlertFilter = {
      ...alertFilter,
      timestamp: recentWindow
    };

    const [
      totalAlerts,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      totalTelemetryLogs,
      totalLiveSnortLogs,
      latestAlert,
      recentTelemetryLogsRaw,
      recentSnortLogsRaw,
      recentAlerts
    ] = await Promise.all([
      Alert.countDocuments(recentAlertFilter),
      Alert.countDocuments({ ...recentAlertFilter, severity: "Critical" }),
      Alert.countDocuments({ ...recentAlertFilter, severity: "High" }),
      Alert.countDocuments({ ...recentAlertFilter, severity: "Medium" }),
      Alert.countDocuments({ ...recentAlertFilter, severity: "Low" }),
      Log.countDocuments(telemetryLogFilter),
      Log.countDocuments(liveSnortFilter),
      Alert.findOne(recentAlertFilter).sort({ timestamp: -1 }),
      Log.find(recentTelemetryFilter).sort({ timestamp: -1 }).limit(500),
      Log.find(recentSnortFilter).sort({ timestamp: -1 }).limit(500),
      Alert.find(recentAlertFilter).sort({ timestamp: -1 }).limit(200)
    ]);

    const recentTelemetryLogs = recentTelemetryLogsRaw.map(normalizeLog);
    const recentSnortLogs = recentSnortLogsRaw.map(normalizeLog);
    const recentMlLogs = recentTelemetryLogs.filter((log) =>
      Boolean(log?.metadata?.idsEngine?.is_anomaly)
    );
    const telemetryCoverage = buildTelemetryCoverage(recentTelemetryLogs);

    const protocolDistribution = groupCounts(
      recentTelemetryLogs.filter(hasDerivedProtocol),
      (log) => log?.derived?.protocol
    );

    const topPorts = groupCounts(
      recentTelemetryLogs.filter(hasDerivedPort),
      (log) => log?.derived?.destPort
    );

    const topAttackTypes = groupCounts(
      recentAlerts,
      (item) => item?.attackType || item?.type || item?.derived?.message || item?.message,
      8
    );

    const topSourceIps = groupCounts(
      recentTelemetryLogs.filter(hasDerivedSrcIp),
      (log) => log?.derived?.srcIp,
      8
    );

    const topDestinationIps = groupCounts(
      recentTelemetryLogs.filter(hasDerivedDestIp),
      (log) => log?.derived?.destIp,
      8
    );

    const classifications = groupCounts(
      recentAlerts,
      (item) =>
        item?.attackType ||
        item?.type ||
        item?.metadata?.classification ||
        item?.derived?.classification,
      8
    );

    const alertSourceDistribution = groupCounts(
      recentAlerts,
      (alert) => alert?.source || "unknown"
    );

    const alertStatusDistribution = groupCounts(
      recentAlerts,
      (alert) => alert?.status || "New"
    );

    const severityDistribution = groupCounts(
      recentAlerts,
      (alert) => alert?.severity || "Unknown"
    );

    const uniqueSourceIps = new Set(
      recentTelemetryLogs.map((log) => log?.derived?.srcIp).filter((value) => !isUnknownLike(value))
    ).size;

    const uniqueDestinationIps = new Set(
      recentTelemetryLogs
        .map((log) => log?.derived?.destIp)
        .filter((value) => !isUnknownLike(value))
    ).size;

    return res.json({
      mode:
        recentTelemetryLogs.length > 0 || recentAlerts.length > 0
          ? "live-monitoring"
          : "waiting-for-telemetry",
      alerts: {
        total: totalAlerts,
        critical: criticalAlerts,
        high: highAlerts,
        medium: mediumAlerts,
        low: lowAlerts,
        sourceDistribution: alertSourceDistribution,
        statusDistribution: alertStatusDistribution,
        severityDistribution
      },
      logs: {
        total: totalTelemetryLogs,
        snortTotal: totalLiveSnortLogs
      },
      traffic: {
        eventsLast24h: recentTelemetryLogs.length,
        uniqueSourceIps,
        uniqueDestinationIps,
        avgPriority: averageMetric(recentTelemetryLogs, (log) => log?.derived?.priority),
        liveSnortEventsLast24h: recentSnortLogs.length,
        liveSnortAlertsLast24h: recentAlerts.filter((alert) => alert.source === "snort").length,
        mlAnomaliesLast24h: recentMlLogs.length,
        telemetryCoverage
      },
      analytics: {
        protocolDistribution,
        topPorts,
        topAttackTypes,
        classifications,
        alertSourceDistribution,
        alertStatusDistribution,
        severityDistribution,
        topSourceIps,
        topDestinationIps,
        timeline: buildTimelineBuckets(recentTelemetryLogs),
        recentLogs: recentTelemetryLogs.slice(0, 12),
        recentAlerts: recentAlerts.slice(0, 8)
      },
      lastDetectionTime:
        latestAlert?.timestamp ||
        recentTelemetryLogs?.[0]?.timestamp ||
        null
    });
  } catch (error) {
    console.error("dashboard getStats error:", error);
    return res.status(500).json({ message: "Failed to fetch stats" });
  }
};

const getHealth = async (req, res) => {
  try {
    const orgFilter = { _org_id: req.orgId };
    const dbStatus = mongoose.connection.readyState === 1 ? "connected" : "disconnected";

    const idsEngineRaw = await getIdsEngineHealth();
    const idsEngine = normalizeIdsEngineHealth(idsEngineRaw);

    const liveSnortFilter = {
      ...orgFilter,
      ...buildSnortLogMatch()
    };

    const [
      lastAlert,
      lastSnortEvent,
      liveSnortEventsLast24h,
      liveSnortEventsRecent,
      recentOnlineAssets
    ] = await Promise.all([
      Alert.findOne(orgFilter).sort({ timestamp: -1 }),
      Log.findOne(liveSnortFilter).sort({ timestamp: -1 }),
      Log.countDocuments({
        ...liveSnortFilter,
        timestamp: { $gte: new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000) }
      }),
      Log.countDocuments({
        ...liveSnortFilter,
        timestamp: { $gte: new Date(Date.now() - LIVE_STATUS_WINDOW_MINS * 60 * 1000) }
      }),
      Asset.countDocuments({
        ...orgFilter,
        agent_status: "online",
        agent_last_seen: { $gte: new Date(Date.now() - AGENT_STATUS_WINDOW_MINS * 60 * 1000) }
      })
    ]);

    const snortStatus =
      liveSnortEventsRecent > 0 || recentOnlineAssets > 0 || liveSnortEventsLast24h > 0
        ? "online"
        : "offline";

    return res.json({
      status: "ok",
      database: dbStatus,
      idsEngine: {
        status: idsEngine.status,
        modelLoaded: idsEngine.modelLoaded,
        usingFallback: idsEngine.usingFallback,
        version: idsEngine.version,
        message: idsEngine.message
      },
      snort: {
        status: snortStatus,
        lastEventAt: lastSnortEvent?.timestamp || null,
        liveEventsLast24h: liveSnortEventsLast24h,
        recentOnlineAssets
      },
      lastDetectionTime: lastAlert?.timestamp || lastSnortEvent?.timestamp || null
    });
  } catch (error) {
    console.error("dashboard getHealth error:", error);
    return res.status(500).json({ message: "Failed to fetch health" });
  }
};

module.exports = { getStats, getHealth };
