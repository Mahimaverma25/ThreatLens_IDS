const mongoose = require("mongoose");

const Alert = require("../models/Alerts");
const Asset = require("../models/Asset");
const Log = require("../models/Log");
const { getIdsEngineHealth } = require("../services/detection.service");
const { getEventStreamHealth } = require("../services/event-stream.service");
const AgentHeartbeat = require("../models/AgentHeartbeat");

const TIME_WINDOW_HOURS = 24;
const LIVE_STATUS_WINDOW_MINS = 5;
const AGENT_STATUS_WINDOW_MINS = 30;
const DETECTION_ALERT_SOURCES = ["snort", "suricata", "rule-engine", "ids-engine-ml", "ids-engine"];

const buildSnortLogMatch = () => ({
  $or: [
    { source: "snort" },
    { source: "suricata" },
    { "metadata.sensorType": { $in: ["snort", "suricata"] } },
    { "metadata.snort": { $exists: true, $ne: null } }
  ]
});

const buildTelemetryLogMatch = () => ({
  $or: [
    { source: "snort" },
    { source: "suricata" },
    { source: "host" },
    { source: "agent" },
    { source: "ids-engine" },
    { source: "rule-engine" },
    { source: "ids-engine-ml" },
    { eventType: "snort.alert" },
    { eventType: { $regex: "^(auth|process|file|service|startup|privilege)\\." } },
    { "metadata.snort": { $exists: true, $ne: null } },
    { "metadata.host": { $exists: true, $ne: null } },
    { "metadata.idsEngine": { $exists: true, $ne: null } }
  ]
});

const buildHostLogMatch = () => ({
  $or: [
    { source: "host" },
    { "metadata.sensorType": "host" },
    { eventType: { $regex: "^(auth|process|file|service|startup|privilege)\\." } },
    { "metadata.host": { $exists: true, $ne: null } }
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
    log?.metadata?.network?.protocol ||
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
    log?.metadata?.network?.sourceIp ||
    log?.ip ||
    log?.metadata?.sourceIp ||
    log?.sourceIp ||
    "Unknown"
  );
};

const getDestIp = (log) => {
  return (
    log?.metadata?.snort?.destIp ||
    log?.metadata?.network?.destinationIp ||
    log?.metadata?.destinationIp ||
    log?.destinationIp ||
    "Unknown"
  );
};

const getDestPort = (log) => {
  const protocol = String(getProtocol(log)).toUpperCase();

  const rawPort =
    log?.metadata?.snort?.destPort ??
    log?.metadata?.network?.destinationPort ??
    log?.metadata?.destinationPort ??
    log?.metadata?.port ??
    log?.metadata?.network?.port ??
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
    algorithm: raw?.algorithm || null,
    trainedAt: raw?.trainedAt || raw?.trained_at || null,
    featureNames: Array.isArray(raw?.featureNames || raw?.feature_names)
      ? raw.featureNames || raw.feature_names
      : [],
    version: raw?.version || null,
    message: raw?.message || null
  };
};

const startOfDay = (value = new Date()) => {
  const date = new Date(value);
  date.setHours(0, 0, 0, 0);
  return date;
};

const startOfWeek = (value = new Date()) => {
  const date = startOfDay(value);
  const day = date.getDay();
  const diff = day === 0 ? 6 : day - 1;
  date.setDate(date.getDate() - diff);
  return date;
};

const buildEndpointRiskRows = (assets, recentAlerts, heartbeats) => {
  const alertsByAsset = recentAlerts.reduce((accumulator, alert) => {
    const assetId = alert?._asset_id?.toString?.();
    if (!assetId) return accumulator;

    accumulator[assetId] = accumulator[assetId] || [];
    accumulator[assetId].push(alert);
    return accumulator;
  }, {});

  const heartbeatByAsset = heartbeats.reduce((accumulator, heartbeat) => {
    const assetId = heartbeat?._asset_id?.toString?.();
    if (!assetId || accumulator[assetId]) return accumulator;
    accumulator[assetId] = heartbeat;
    return accumulator;
  }, {});

  const severityWeights = {
    critical: 40,
    high: 24,
    medium: 12,
    low: 6
  };

  return assets
    .map((asset) => {
      const assetId = asset?._id?.toString?.();
      const assetAlerts = alertsByAsset[assetId] || [];
      const heartbeat = heartbeatByAsset[assetId];
      const telemetryTypes = Array.isArray(asset.telemetry_types) ? asset.telemetry_types : [];
      const coverageScore = Math.min(100, telemetryTypes.length * 20 + (heartbeat ? 15 : 0));
      const riskScore = Math.min(
        100,
        assetAlerts.reduce((sum, alert) => {
          const weight = severityWeights[normalizeText(alert?.severity).toLowerCase()] || 4;
          return sum + weight;
        }, asset.agent_status === "online" ? 10 : 24)
      );

      const highestSeverity =
        assetAlerts
          .map((alert) => normalizeText(alert?.severity).toLowerCase())
          .find((severity) => ["critical", "high", "medium", "low"].includes(severity)) || "low";

      return {
        assetId: asset.asset_id,
        hostname: asset.hostname || asset.asset_name || asset.asset_id,
        platform: asset.host_platform || "Unknown",
        environment: asset.asset_environment || "production",
        status: asset.agent_status || "offline",
        coverageScore,
        riskScore,
        openAlerts: assetAlerts.length,
        highestSeverity,
        lastSeenAt: asset.agent_last_seen || heartbeat?.receivedAt || null,
        telemetryTypes
      };
    })
    .sort((left, right) => right.riskScore - left.riskScore)
    .slice(0, 8);
};

const buildKillChainCoverage = (logs, alerts) => {
  const stages = [
    {
      key: "Initial Access",
      matcher: (value) =>
        /(initial access|phishing|login|brute|credential|auth)/i.test(value)
    },
    {
      key: "Execution",
      matcher: (value) =>
        /(execution|process|powershell|cmd|script|wmic)/i.test(value)
    },
    {
      key: "Persistence",
      matcher: (value) =>
        /(persistence|startup|service|registry|autorun)/i.test(value)
    },
    {
      key: "Privilege Escalation",
      matcher: (value) =>
        /(privilege|sudo|admin|escalat)/i.test(value)
    },
    {
      key: "Defense Evasion",
      matcher: (value) =>
        /(defense evasion|disable|tamper|evasion|obfusc)/i.test(value)
    },
    {
      key: "Discovery",
      matcher: (value) =>
        /(discovery|recon|scan|enumerat|inventory)/i.test(value)
    },
    {
      key: "Lateral Movement",
      matcher: (value) =>
        /(lateral|remote|smb|rdp|psexec|pivot)/i.test(value)
    },
    {
      key: "Exfiltration",
      matcher: (value) =>
        /(exfil|download|upload|dns tunnel|leak)/i.test(value)
    }
  ];

  const corpus = [
    ...logs.map((log) =>
      [
        getMessage(log),
        deriveClassification(log),
        normalizeText(log?.eventType)
      ].join(" ")
    ),
    ...alerts.map((alert) =>
      [
        normalizeText(alert?.type),
        normalizeText(alert?.attackType),
        normalizeText(alert?.metadata?.classification)
      ].join(" ")
    )
  ];

  return stages.map((stage) => {
    const hits = corpus.filter((item) => stage.matcher(item)).length;
    return {
      stage: stage.key,
      detections: hits,
      coverage: Math.min(100, hits * 12 + (hits > 0 ? 18 : 0))
    };
  });
};

const buildIncidentMatrix = (alerts) => {
  const severities = ["Critical", "High", "Medium", "Low"];
  const statuses = ["New", "Acknowledged", "Investigating", "Resolved"];

  return severities.flatMap((severity) =>
    statuses.map((status) => ({
      severity,
      status,
      value: alerts.filter(
        (alert) => normalizeText(alert?.severity) === severity && normalizeText(alert?.status) === status
      ).length
    }))
  );
};

const getOverview = async (req, res) => {
  try {
    const orgFilter = { _org_id: req.orgId };
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - TIME_WINDOW_HOURS * 60 * 60 * 1000);
    const dayStart = startOfDay(now);
    const weekStart = startOfWeek(now);
    const recentHeartbeatWindow = new Date(now.getTime() - AGENT_STATUS_WINDOW_MINS * 60 * 1000);

    const telemetryLogFilter = {
      ...orgFilter,
      ...buildTelemetryLogMatch()
    };

    const hostTelemetryFilter = {
      ...orgFilter,
      ...buildHostLogMatch()
    };

    const detectionAlertFilter = {
      ...orgFilter,
      source: { $in: DETECTION_ALERT_SOURCES }
    };

    const [
      assets,
      recentAlerts,
      recentLogsRaw,
      hostLogsRaw,
      heartbeats,
      alertTotal,
      totalAssets,
      onlineAssets,
      resolvedToday,
      newToday
    ] = await Promise.all([
      Asset.find(orgFilter).sort({ agent_last_seen: -1 }).limit(50),
      Alert.find({ ...detectionAlertFilter, timestamp: { $gte: weekStart } }).sort({ timestamp: -1 }).limit(300),
      Log.find({ ...telemetryLogFilter, timestamp: { $gte: oneDayAgo } }).sort({ timestamp: -1 }).limit(500),
      Log.find({ ...hostTelemetryFilter, timestamp: { $gte: oneDayAgo } }).sort({ timestamp: -1 }).limit(300),
      AgentHeartbeat.find({ ...orgFilter, receivedAt: { $gte: weekStart } }).sort({ receivedAt: -1 }).limit(200),
      Alert.countDocuments({ ...detectionAlertFilter, timestamp: { $gte: oneDayAgo } }),
      Asset.countDocuments(orgFilter),
      Asset.countDocuments({
        ...orgFilter,
        agent_status: "online",
        agent_last_seen: { $gte: recentHeartbeatWindow }
      }),
      Alert.countDocuments({
        ...detectionAlertFilter,
        status: "Resolved",
        resolvedAt: { $gte: dayStart }
      }),
      Alert.countDocuments({
        ...detectionAlertFilter,
        timestamp: { $gte: dayStart }
      })
    ]);

    const recentLogs = recentLogsRaw.map(normalizeLog);
    const hostLogs = hostLogsRaw.map(normalizeLog);
    const alertStatusDistribution = groupCounts(recentAlerts, (alert) => alert?.status || "New", 8);
    const topClassifications = groupCounts(
      recentAlerts,
      (alert) => alert?.attackType || alert?.type || alert?.metadata?.classification,
      6
    );
    const topHosts = groupCounts(
      hostLogs,
      (log) => log?.metadata?.hostname || log?.metadata?.host || log?._asset_id || "Unknown Host",
      6
    );
    const topTalkers = groupCounts(recentLogs.filter(hasDerivedSrcIp), (log) => log?.derived?.srcIp, 6);
    const topTargets = groupCounts(recentLogs.filter(hasDerivedDestIp), (log) => log?.derived?.destIp, 6);
    const recentCritical = recentAlerts.filter((alert) => normalizeText(alert?.severity).toLowerCase() === "critical").length;
    const recentHigh = recentAlerts.filter((alert) => normalizeText(alert?.severity).toLowerCase() === "high").length;
    const suspiciousCommands = hostLogs.filter((log) =>
      /(powershell|encodedcommand|wmic|cmd\.exe|regsvr32|rundll32)/i.test(getMessage(log))
    ).length;
    const fileIntegrityChanges = hostLogs.filter((log) =>
      /(file|integrity|watch)/i.test(deriveClassification(log))
    ).length;
    const authenticationSignals = hostLogs.filter((log) =>
      /(auth|login|credential|brute)/i.test(`${getMessage(log)} ${deriveClassification(log)}`)
    ).length;
    const openIncidents = recentAlerts.filter((alert) => normalizeText(alert?.status).toLowerCase() !== "resolved").length;

    return res.json({
      generatedAt: now.toISOString(),
      executive: {
        monitoredEndpoints: totalAssets,
        onlineEndpoints: onlineAssets,
        alertsLast24h: alertTotal,
        detectionsToday: newToday,
        resolvedToday,
        openIncidents,
        telemetryEventsLast24h: recentLogs.length,
        hostEventsLast24h: hostLogs.length
      },
      posture: {
        criticalAlerts: recentCritical,
        highAlerts: recentHigh,
        suspiciousCommands,
        fileIntegrityChanges,
        authenticationSignals,
        sensorCoveragePercent: totalAssets > 0 ? Math.round((onlineAssets / totalAssets) * 100) : 0
      },
      detections: {
        timeline: buildTimelineBuckets(recentLogs),
        statusDistribution: alertStatusDistribution,
        topClassifications,
        topTalkers,
        topTargets
      },
      endpoints: {
        riskTable: buildEndpointRiskRows(assets, recentAlerts, heartbeats),
        topHosts
      },
      integrity: {
        telemetryCoverage: buildTelemetryCoverage(recentLogs),
        protocolDistribution: groupCounts(
          recentLogs.filter(hasDerivedProtocol),
          (log) => log?.derived?.protocol,
          6
        ),
        topPorts: groupCounts(
          recentLogs.filter(hasDerivedPort),
          (log) => log?.derived?.destPort,
          8
        )
      },
      operations: {
        killChainCoverage: buildKillChainCoverage(recentLogs, recentAlerts),
        incidentMatrix: buildIncidentMatrix(recentAlerts),
        liveFeed: recentLogs.slice(0, 10).map((log) => ({
          id: log._id,
          timestamp: log.timestamp,
          title: getMessage(log),
          classification: log?.derived?.classification,
          source: log?.source || log?.metadata?.sensorType || "unknown",
          severity: normalizeText(log?.severity || log?.level || "info").toLowerCase(),
          host: log?.metadata?.hostname || log?.metadata?.host || "Unknown Host"
        }))
      }
    });
  } catch (error) {
    console.error("dashboard getOverview error:", error);
    return res.status(500).json({ message: "Failed to fetch dashboard overview" });
  }
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

    const hostTelemetryFilter = {
      ...orgFilter,
      ...buildHostLogMatch()
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
      totalHostLogs,
      latestAlert,
      recentTelemetryLogsRaw,
      recentSnortLogsRaw,
      recentHostLogsRaw,
      recentAlerts
    ] = await Promise.all([
      Alert.countDocuments(recentAlertFilter),
      Alert.countDocuments({ ...recentAlertFilter, severity: "Critical" }),
      Alert.countDocuments({ ...recentAlertFilter, severity: "High" }),
      Alert.countDocuments({ ...recentAlertFilter, severity: "Medium" }),
      Alert.countDocuments({ ...recentAlertFilter, severity: "Low" }),
      Log.countDocuments(telemetryLogFilter),
      Log.countDocuments(liveSnortFilter),
      Log.countDocuments({
        ...hostTelemetryFilter,
        timestamp: recentWindow
      }),
      Alert.findOne(recentAlertFilter).sort({ timestamp: -1 }),
      Log.find(recentTelemetryFilter).sort({ timestamp: -1 }).limit(500),
      Log.find(recentSnortFilter).sort({ timestamp: -1 }).limit(500),
      Log.find({
        ...hostTelemetryFilter,
        timestamp: recentWindow
      }).sort({ timestamp: -1 }).limit(500),
      Alert.find(recentAlertFilter).sort({ timestamp: -1 }).limit(200)
    ]);

    const recentTelemetryLogs = recentTelemetryLogsRaw.map(normalizeLog);
    const recentSnortLogs = recentSnortLogsRaw.map(normalizeLog);
    const recentHostLogs = recentHostLogsRaw.map(normalizeLog);
    const recentMlLogs = recentTelemetryLogs.filter((log) =>
      Boolean(log?.metadata?.idsEngine?.is_anomaly)
    );
    const recentHostAlerts = recentAlerts.filter((alert) =>
      ["rule-engine", "ids-engine-ml"].includes(alert.source) &&
      (alert?.metadata?.category === "host" || alert?.type?.toLowerCase?.().includes("host"))
    );
    const sensorDistribution = groupCounts(
      recentTelemetryLogs,
      (log) => log?.metadata?.sensorType || log?.source || "unknown",
      8
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
        snortTotal: totalLiveSnortLogs,
        hostTotal: totalHostLogs
      },
      traffic: {
        eventsLast24h: recentTelemetryLogs.length,
        uniqueSourceIps,
        uniqueDestinationIps,
        avgPriority: averageMetric(recentTelemetryLogs, (log) => log?.derived?.priority),
        liveSnortEventsLast24h: recentSnortLogs.length,
        hostEventsLast24h: recentHostLogs.length,
        liveSnortAlertsLast24h: recentAlerts.filter((alert) => alert.source === "snort").length,
        hostAlertsLast24h: recentHostAlerts.length,
        mlAnomaliesLast24h: recentMlLogs.length,
        sensorDistribution,
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
    const stream = getEventStreamHealth();

    const liveSnortFilter = {
      ...orgFilter,
      ...buildSnortLogMatch()
    };
    const hostTelemetryFilter = {
      ...orgFilter,
      ...buildHostLogMatch()
    };

    const [
      lastAlert,
      lastSnortEvent,
      lastHostEvent,
      lastHeartbeat,
      liveSnortEventsLast24h,
      liveHostEventsLast24h,
      liveSnortEventsRecent,
      liveHostEventsRecent,
      recentOnlineAssets,
      recentHeartbeats
    ] = await Promise.all([
      Alert.findOne(orgFilter).sort({ timestamp: -1 }),
      Log.findOne(liveSnortFilter).sort({ timestamp: -1 }),
      Log.findOne(hostTelemetryFilter).sort({ timestamp: -1 }),
      AgentHeartbeat.findOne(orgFilter).sort({ receivedAt: -1 }),
      Log.countDocuments({
        ...liveSnortFilter,
        timestamp: { $gte: new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000) }
      }),
      Log.countDocuments({
        ...hostTelemetryFilter,
        timestamp: { $gte: new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000) }
      }),
      Log.countDocuments({
        ...liveSnortFilter,
        timestamp: { $gte: new Date(Date.now() - LIVE_STATUS_WINDOW_MINS * 60 * 1000) }
      }),
      Log.countDocuments({
        ...hostTelemetryFilter,
        timestamp: { $gte: new Date(Date.now() - LIVE_STATUS_WINDOW_MINS * 60 * 1000) }
      }),
      Asset.countDocuments({
        ...orgFilter,
        agent_status: "online",
        agent_last_seen: { $gte: new Date(Date.now() - AGENT_STATUS_WINDOW_MINS * 60 * 1000) }
      }),
      AgentHeartbeat.countDocuments({
        ...orgFilter,
        receivedAt: { $gte: new Date(Date.now() - AGENT_STATUS_WINDOW_MINS * 60 * 1000) }
      }),
    ]);

    const snortStatus =
      liveSnortEventsRecent > 0 || recentOnlineAssets > 0 || recentHeartbeats > 0 || liveSnortEventsLast24h > 0
        ? "online"
        : "offline";
    const hostStatus =
      liveHostEventsRecent > 0 || recentHeartbeats > 0 || liveHostEventsLast24h > 0
        ? "online"
        : "offline";

    return res.json({
      status: "ok",
      database: dbStatus,
      idsEngine: {
        status: idsEngine.status,
        modelLoaded: idsEngine.modelLoaded,
        usingFallback: idsEngine.usingFallback,
        algorithm: idsEngine.algorithm,
        trainedAt: idsEngine.trainedAt,
        featureNames: idsEngine.featureNames,
        version: idsEngine.version,
        message: idsEngine.message
      },
      stream,
      host: {
        status: hostStatus,
        lastEventAt: lastHostEvent?.timestamp || null,
        liveEventsLast24h: liveHostEventsLast24h,
      },
      collector: lastHeartbeat
        ? {
            status: lastHeartbeat.status || "unknown",
            lastHeartbeatAt: lastHeartbeat.receivedAt || null,
            agentType: lastHeartbeat.agent_type || "unknown",
            hostPlatform: lastHeartbeat.host_platform || "",
            hostname: lastHeartbeat.hostname || "",
            queueDepth: lastHeartbeat.queue_depth || 0,
            telemetryTypes: Array.isArray(lastHeartbeat.telemetry_types)
              ? lastHeartbeat.telemetry_types
              : [],
            assetId: lastHeartbeat._asset_id?.toString?.() || null,
            metadata: lastHeartbeat.metadata || {}
          }
        : {
            status: recentHeartbeats > 0 ? "online" : "offline",
            lastHeartbeatAt: null,
            agentType: null,
            hostPlatform: "",
            hostname: "",
            queueDepth: 0,
            telemetryTypes: [],
            assetId: null,
            metadata: {}
          },
      snort: {
        status: snortStatus,
        lastEventAt: lastSnortEvent?.timestamp || null,
        liveEventsLast24h: liveSnortEventsLast24h,
        recentOnlineAssets,
        recentHeartbeats
      },
      lastDetectionTime: lastAlert?.timestamp || lastHostEvent?.timestamp || lastSnortEvent?.timestamp || null
    });
  } catch (error) {
    console.error("dashboard getHealth error:", error);
    return res.status(500).json({ message: "Failed to fetch health" });
  }
};

module.exports = { getStats, getHealth, getOverview };
