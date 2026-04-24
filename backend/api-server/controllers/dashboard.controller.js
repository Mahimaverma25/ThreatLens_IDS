const mongoose = require("mongoose");

const Alert = require("../models/Alerts");
const Asset = require("../models/Asset");
const Incident = require("../models/Incident");
const Log = require("../models/Log");
const AgentHeartbeat = require("../models/AgentHeartbeat");
const { getIdsEngineHealth } = require("../services/detection.service");
const { getEventStreamHealth } = require("../services/event-stream.service");

const TIME_WINDOW_HOURS = 24;
const LIVE_STATUS_WINDOW_MINS = 5;
const AGENT_STATUS_WINDOW_MINS = 30;
const DETECTION_ALERT_SOURCES = ["snort", "suricata", "rule-engine", "ids-engine-ml", "ids-engine"];

const trimText = (value) => String(value ?? "").trim();

const isUnknownLike = (value) => {
  const normalized = trimText(value).toLowerCase();
  return !normalized || normalized === "unknown" || normalized === "n/a" || normalized === "-";
};

const titleCase = (value) => {
  const normalized = trimText(value);
  if (!normalized) return "Unknown";
  return normalized
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
};

const buildSnortLogMatch = () => ({
  $or: [
    { source: "snort" },
    { source: "suricata" },
    { "metadata.sensorType": { $in: ["snort", "suricata", "nids"] } },
    { "metadata.snort": { $exists: true, $ne: null } },
  ],
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
    { "metadata.idsEngine": { $exists: true, $ne: null } },
  ],
});

const buildHostLogMatch = () => ({
  $or: [
    { source: "host" },
    { "metadata.sensorType": { $in: ["host", "hids"] } },
    { eventType: { $regex: "^(auth|process|file|service|startup|privilege)\\." } },
    { "metadata.host": { $exists: true, $ne: null } },
  ],
});

const getProtocol = (log) =>
  trimText(
    log?.metadata?.normalized?.protocol ||
      log?.metadata?.protocol ||
      log?.metadata?.appProtocol ||
      log?.metadata?.network?.protocol ||
      log?.metadata?.snort?.protocol ||
      log?.protocol ||
      "Unknown"
  );

const getMessage = (log) =>
  trimText(
    log?.metadata?.snort?.message ||
      log?.metadata?.normalized?.message ||
      log?.message ||
      log?.signature ||
      "Unknown Event"
  );

const getSrcIp = (log) =>
  trimText(
    log?.metadata?.normalized?.srcIp ||
      log?.metadata?.sourceIp ||
      log?.metadata?.network?.sourceIp ||
      log?.metadata?.snort?.srcIp ||
      log?.ip ||
      "Unknown"
  );

const getDestIp = (log) =>
  trimText(
    log?.metadata?.normalized?.destIp ||
      log?.metadata?.destinationIp ||
      log?.metadata?.network?.destinationIp ||
      log?.metadata?.snort?.destIp ||
      log?.destinationIp ||
      "Unknown"
  );

const getDestPort = (log) => {
  const port =
    log?.metadata?.normalized?.port ??
    log?.metadata?.destinationPort ??
    log?.metadata?.port ??
    log?.metadata?.network?.destinationPort ??
    log?.metadata?.snort?.destPort ??
    log?.destinationPort ??
    null;

  const protocol = getProtocol(log).toUpperCase();
  if (port !== null && port !== undefined && trimText(port) !== "") {
    return String(port).trim();
  }
  if (protocol === "ICMP") return "N/A (ICMP)";
  return "Unknown";
};

const getPriority = (log) => {
  const raw =
    log?.metadata?.snort?.priority ??
    log?.priority ??
    log?.severityScore ??
    0;
  const numeric = Number(raw);
  return Number.isFinite(numeric) ? numeric : 0;
};

const deriveClassification = (log) => {
  const explicit =
    log?.metadata?.classification ||
    log?.metadata?.snort?.classification ||
    log?.metadata?.attackType;

  if (!isUnknownLike(explicit)) {
    return titleCase(explicit);
  }

  const message = getMessage(log).toLowerCase();
  const protocol = getProtocol(log).toLowerCase();

  if (message.includes("port scan") || message.includes("scan")) return "Port Scan";
  if (message.includes("brute")) return "Brute Force";
  if (message.includes("dns")) return "DNS Abuse";
  if (message.includes("exfil")) return "Data Exfiltration";
  if (message.includes("powershell") || message.includes("wmic")) return "Suspicious Process";
  if (message.includes("integrity") || message.includes("file")) return "File Integrity Change";
  if (message.includes("privilege") || message.includes("sudo") || message.includes("root")) {
    return "Privilege Escalation";
  }
  if (message.includes("icmp")) return "ICMP Flood";
  if (message.includes("ddos") || message.includes("dos") || message.includes("flood")) {
    return "DoS / DDoS";
  }
  if (protocol === "ICMP") return "ICMP Activity";
  if (protocol === "UDP") return "UDP Activity";
  if (protocol === "TCP") return "TCP Activity";

  return "Security Event";
};

const normalizeLog = (log) => {
  const sourceObject = log?.toObject?.() ? log.toObject() : log;

  return {
    ...sourceObject,
    derived: {
      message: getMessage(sourceObject),
      protocol: getProtocol(sourceObject),
      classification: deriveClassification(sourceObject),
      srcIp: getSrcIp(sourceObject),
      destIp: getDestIp(sourceObject),
      destPort: getDestPort(sourceObject),
      priority: getPriority(sourceObject),
    },
  };
};

const groupCounts = (items, accessor, limit = 8) => {
  const counts = new Map();

  items.forEach((item) => {
    const key = trimText(accessor(item));
    const normalized = isUnknownLike(key) ? "Unknown" : key;
    counts.set(normalized, (counts.get(normalized) || 0) + 1);
  });

  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, limit);
};

const hasDerivedProtocol = (log) => !isUnknownLike(log?.derived?.protocol);
const hasDerivedSrcIp = (log) => !isUnknownLike(log?.derived?.srcIp);
const hasDerivedDestIp = (log) => !isUnknownLike(log?.derived?.destIp);
const hasDerivedPort = (log) => {
  const value = trimText(log?.derived?.destPort);
  return Boolean(value) && value !== "Unknown" && !value.startsWith("N/A");
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
    unknownPort: Math.max(0, total - withPort),
  };
};

const averageMetric = (logs, accessor) => {
  if (!logs.length) return 0;
  const total = logs.reduce((sum, log) => sum + Number(accessor(log) || 0), 0);
  return Number((total / logs.length).toFixed(2));
};

const isSecurityRelevantLog = (log) => {
  const source = trimText(log?.source || log?.metadata?.sensorType).toLowerCase();
  const eventType = trimText(log?.eventType).toLowerCase();
  const message = getMessage(log).toLowerCase();
  const classification = deriveClassification(log).toLowerCase();
  const anomaly = Boolean(log?.metadata?.idsEngine?.is_anomaly);
  const priority = getPriority(log);

  if (anomaly) return true;
  if (["snort", "suricata", "rule-engine", "ids-engine", "ids-engine-ml"].includes(source)) return true;
  if (priority > 0) return true;
  if (/auth\.failure|snort\.alert|privilege\.escalation|file\.change/.test(eventType)) return true;
  return /(ddos|dos|flood|scan|brute|dns abuse|icmp|exfil|powershell|wmic|encodedcommand|rundll32|regsvr32|privilege|suspicious|malware|exploit)/.test(
    `${message} ${classification}`
  );
};

const buildAlertTimelineBuckets = (alerts) => {
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
      anomalies: 0,
    });
  }

  alerts.forEach((alert) => {
    if (!alert?.timestamp) return;
    const date = new Date(alert.timestamp);
    if (Number.isNaN(date.getTime())) return;
    const key = `${String(date.getHours()).padStart(2, "0")}:00`;
    const bucket = buckets.get(key);
    if (!bucket) return;

    const severity = trimText(alert?.severity).toLowerCase();
    const source = trimText(alert?.source).toLowerCase();

    bucket.events += 1;
    bucket.priorityScore += severity === "critical" ? 5 : severity === "high" ? 3 : severity === "medium" ? 2 : 1;
    if (severity === "critical") bucket.criticalEvents += 1;
    if (severity === "high") bucket.highEvents += 1;
    if (source === "ids-engine" || source === "ids-engine-ml") bucket.anomalies += 1;
  });

  return [...buckets.values()];
};

const buildSeverityDistribution = (alerts) => {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

  alerts.forEach((alert) => {
    const severity = titleCase(alert?.severity);
    if (Object.prototype.hasOwnProperty.call(counts, severity)) {
      counts[severity] += 1;
    }
  });

  return Object.entries(counts).map(([name, value]) => ({ name, value }));
};

const buildIpCounts = (alerts, logs, accessor, limit = 5) => {
  const counts = new Map();

  [...alerts, ...logs].forEach((item) => {
    const value = trimText(accessor(item));
    if (isUnknownLike(value)) return;
    counts.set(value, (counts.get(value) || 0) + 1);
  });

  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, limit);
};

const normalizeIdsEngineHealth = (idsEngine) => {
  const raw = idsEngine || {};
  const status = trimText(raw?.status || raw?.state || raw?.health || raw);

  return {
    status: status ? status.toLowerCase() : "unknown",
    modelLoaded: raw?.modelLoaded ?? raw?.model_loaded ?? raw?.isModelLoaded ?? null,
    usingFallback: raw?.usingFallback ?? raw?.using_fallback ?? raw?.fallback ?? null,
    algorithm: raw?.algorithm || null,
    trainedAt: raw?.trainedAt || raw?.trained_at || null,
    featureNames: Array.isArray(raw?.featureNames || raw?.feature_names)
      ? raw.featureNames || raw.feature_names
      : [],
    version: raw?.version || null,
    message: raw?.message || null,
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

const buildEndpointRiskRows = (assets, alerts, heartbeats) => {
  const alertsByAsset = alerts.reduce((accumulator, alert) => {
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

  return assets
    .map((asset) => {
      const assetId = asset?._id?.toString?.();
      const assetAlerts = alertsByAsset[assetId] || [];
      const heartbeat = heartbeatByAsset[assetId];
      const telemetryTypes = Array.isArray(asset.telemetry_types) ? asset.telemetry_types : [];

      const criticalAlerts = assetAlerts.filter((alert) => trimText(alert?.severity).toLowerCase() === "critical").length;
      const highAlerts = assetAlerts.filter((alert) => trimText(alert?.severity).toLowerCase() === "high").length;
      const mediumAlerts = assetAlerts.filter((alert) => trimText(alert?.severity).toLowerCase() === "medium").length;

      return {
        assetId: asset.asset_id,
        hostname: asset.hostname || asset.asset_name || asset.asset_id,
        platform: asset.host_platform || "Unknown",
        environment: asset.asset_environment || "production",
        status: asset.agent_status || "offline",
        coverageScore: Math.min(100, telemetryTypes.length * 20 + (heartbeat ? 15 : 0)),
        riskScore: Math.min(100, criticalAlerts * 5 + highAlerts * 3 + mediumAlerts * 2),
        openAlerts: assetAlerts.filter((alert) => trimText(alert?.status).toLowerCase() !== "resolved").length,
        highestSeverity:
          assetAlerts
            .map((alert) => trimText(alert?.severity).toLowerCase())
            .find((severity) => ["critical", "high", "medium", "low"].includes(severity)) || "low",
        lastSeenAt: asset.agent_last_seen || heartbeat?.receivedAt || null,
        telemetryTypes,
      };
    })
    .sort((left, right) => right.riskScore - left.riskScore)
    .slice(0, 8);
};

const buildKillChainCoverage = (logs, alerts) => {
  const stages = [
    { stage: "Initial Access", matcher: /(phishing|login|brute|credential|web brute|ssh brute)/i },
    { stage: "Execution", matcher: /(process|powershell|wmic|rundll32|regsvr32|encodedcommand)/i },
    { stage: "Persistence", matcher: /(file integrity|startup|service|cron|authorized_keys)/i },
    { stage: "Privilege Escalation", matcher: /(privilege|sudo|root|admin)/i },
    { stage: "Discovery", matcher: /(scan|port scan|recon)/i },
    { stage: "Exfiltration", matcher: /(exfiltration|dns abuse)/i },
  ];

  const corpus = [
    ...logs.map((log) => `${getMessage(log)} ${deriveClassification(log)} ${trimText(log?.eventType)}`),
    ...alerts.map((alert) => `${trimText(alert?.attackType)} ${trimText(alert?.type)}`),
  ];

  return stages.map((stage) => {
    const hits = corpus.filter((value) => stage.matcher.test(value)).length;
    return {
      stage: stage.stage,
      detections: hits,
      coverage: Math.min(100, hits * 14 + (hits > 0 ? 12 : 0)),
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
        (alert) => titleCase(alert?.severity) === severity && titleCase(alert?.status) === status
      ).length,
    }))
  );
};

const getOverview = async (req, res) => {
  try {
    const orgFilter = { _org_id: req.orgId };
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - TIME_WINDOW_HOURS * 60 * 60 * 1000);
    const weekStart = startOfWeek(now);
    const dayStart = startOfDay(now);
    const recentHeartbeatWindow = new Date(now.getTime() - AGENT_STATUS_WINDOW_MINS * 60 * 1000);

    const telemetryLogFilter = { ...orgFilter, ...buildTelemetryLogMatch() };
    const hostTelemetryFilter = { ...orgFilter, ...buildHostLogMatch() };
    const detectionAlertFilter = { ...orgFilter, source: { $in: DETECTION_ALERT_SOURCES } };

    const [assets, alerts, recentLogsRaw, hostLogsRaw, heartbeats, totalAssets, onlineAssets, resolvedToday, detectionsToday, openIncidents] =
      await Promise.all([
        Asset.find(orgFilter).sort({ agent_last_seen: -1 }).limit(50),
        Alert.find({ ...detectionAlertFilter, timestamp: { $gte: weekStart } }).sort({ timestamp: -1 }).limit(300),
        Log.find({ ...telemetryLogFilter, timestamp: { $gte: oneDayAgo } }).sort({ timestamp: -1 }).limit(500),
        Log.find({ ...hostTelemetryFilter, timestamp: { $gte: oneDayAgo } }).sort({ timestamp: -1 }).limit(300),
        AgentHeartbeat.find({ ...orgFilter, receivedAt: { $gte: weekStart } }).sort({ receivedAt: -1 }).limit(200),
        Asset.countDocuments(orgFilter),
        Asset.countDocuments({
          ...orgFilter,
          agent_status: "online",
          agent_last_seen: { $gte: recentHeartbeatWindow },
        }),
        Alert.countDocuments({ ...detectionAlertFilter, status: "Resolved", resolvedAt: { $gte: dayStart } }),
        Alert.countDocuments({ ...detectionAlertFilter, timestamp: { $gte: dayStart } }),
        Incident.countDocuments({
          ...orgFilter,
          status: { $in: ["Open", "Acknowledged", "Investigating", "Contained"] },
        }),
      ]);

    const normalizedLogs = recentLogsRaw.map(normalizeLog);
    const hostLogs = hostLogsRaw.map(normalizeLog);
    const securityRelevantLogs = normalizedLogs.filter(isSecurityRelevantLog);

    return res.json({
      generatedAt: now.toISOString(),
      executive: {
        monitoredEndpoints: totalAssets,
        onlineEndpoints: onlineAssets,
        alertsLast24h: alerts.length,
        detectionsToday,
        resolvedToday,
        openIncidents,
        telemetryEventsLast24h: normalizedLogs.length,
        hostEventsLast24h: hostLogs.length,
      },
      posture: {
        criticalAlerts: alerts.filter((alert) => titleCase(alert?.severity) === "Critical").length,
        highAlerts: alerts.filter((alert) => titleCase(alert?.severity) === "High").length,
        suspiciousCommands: hostLogs.filter((log) => /(powershell|wmic|encodedcommand|rundll32|regsvr32)/i.test(getMessage(log))).length,
        fileIntegrityChanges: hostLogs.filter((log) => /file integrity|file change|integrity/i.test(`${deriveClassification(log)} ${getMessage(log)}`)).length,
        authenticationSignals: hostLogs.filter((log) => /(auth|login|credential|brute)/i.test(`${deriveClassification(log)} ${getMessage(log)}`)).length,
        sensorCoveragePercent: totalAssets > 0 ? Math.round((onlineAssets / totalAssets) * 100) : 0,
      },
      detections: {
        timeline: buildAlertTimelineBuckets(alerts),
        statusDistribution: groupCounts(alerts, (alert) => alert?.status || "New", 8),
        topClassifications: groupCounts(alerts, (alert) => alert?.attackType || alert?.type || "Unknown", 5),
        topTalkers: buildIpCounts(alerts, securityRelevantLogs, (item) => item?.ip || item?.derived?.srcIp, 5),
        topTargets: buildIpCounts(alerts, securityRelevantLogs, (item) => item?.metadata?.destinationIp || item?.metadata?.snort?.destIp || item?.derived?.destIp, 5),
      },
      endpoints: {
        riskTable: buildEndpointRiskRows(assets, alerts, heartbeats),
        topHosts: groupCounts(hostLogs, (log) => log?.metadata?.hostname || log?.metadata?.host || "Unknown Host", 6),
      },
      integrity: {
        telemetryCoverage: buildTelemetryCoverage(normalizedLogs),
        protocolDistribution: groupCounts(normalizedLogs.filter(hasDerivedProtocol), (log) => log?.derived?.protocol, 6),
        topPorts: groupCounts(normalizedLogs.filter(hasDerivedPort), (log) => log?.derived?.destPort, 8),
      },
      operations: {
        killChainCoverage: buildKillChainCoverage(normalizedLogs, alerts),
        incidentMatrix: buildIncidentMatrix(alerts),
        liveFeed: securityRelevantLogs.slice(0, 10).map((log) => ({
          id: log._id,
          timestamp: log.timestamp,
          title: getMessage(log),
          classification: log?.derived?.classification,
          source: log?.source || log?.metadata?.sensorType || "unknown",
          severity: trimText(log?.metadata?.severity || log?.level || "info").toLowerCase(),
          host: log?.metadata?.hostname || log?.metadata?.host || "Unknown Host",
        })),
      },
    });
  } catch (error) {
    console.error("dashboard getOverview error:", error);
    return res.status(500).json({ message: "Failed to fetch dashboard overview" });
  }
};

const getStats = async (req, res) => {
  try {
    const orgFilter = { _org_id: req.orgId };
    const recentWindow = new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000);

    const telemetryLogFilter = { ...orgFilter, ...buildTelemetryLogMatch() };
    const hostTelemetryFilter = { ...orgFilter, ...buildHostLogMatch() };
    const liveSnortFilter = { ...orgFilter, ...buildSnortLogMatch() };
    const alertFilter = { ...orgFilter, source: { $in: DETECTION_ALERT_SOURCES } };
    const recentAlertFilter = { ...alertFilter, timestamp: { $gte: recentWindow } };

    const [
      totalAlerts,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      openIncidents,
      totalTelemetryLogs,
      totalLiveSnortLogs,
      totalHostLogs,
      latestAlert,
      recentTelemetryLogsRaw,
      recentSnortLogsRaw,
      recentHostLogsRaw,
      recentAlerts,
      allAlerts,
    ] = await Promise.all([
      Alert.countDocuments(alertFilter),
      Alert.countDocuments({ ...alertFilter, severity: "Critical" }),
      Alert.countDocuments({ ...alertFilter, severity: "High" }),
      Alert.countDocuments({ ...alertFilter, severity: "Medium" }),
      Alert.countDocuments({ ...alertFilter, severity: "Low" }),
      Incident.countDocuments({
        ...orgFilter,
        status: { $in: ["Open", "Acknowledged", "Investigating", "Contained"] },
      }),
      Log.countDocuments({ ...telemetryLogFilter, timestamp: { $gte: recentWindow } }),
      Log.countDocuments({ ...liveSnortFilter, timestamp: { $gte: recentWindow } }),
      Log.countDocuments({ ...hostTelemetryFilter, timestamp: { $gte: recentWindow } }),
      Alert.findOne(alertFilter).sort({ timestamp: -1 }),
      Log.find({ ...telemetryLogFilter, timestamp: { $gte: recentWindow } }).sort({ timestamp: -1 }).limit(500),
      Log.find({ ...liveSnortFilter, timestamp: { $gte: recentWindow } }).sort({ timestamp: -1 }).limit(500),
      Log.find({ ...hostTelemetryFilter, timestamp: { $gte: recentWindow } }).sort({ timestamp: -1 }).limit(500),
      Alert.find(recentAlertFilter).sort({ timestamp: -1 }).limit(200),
      Alert.find(alertFilter).sort({ timestamp: -1 }).limit(1500),
    ]);

    const recentTelemetryLogs = recentTelemetryLogsRaw.map(normalizeLog);
    const recentSnortLogs = recentSnortLogsRaw.map(normalizeLog);
    const recentHostLogs = recentHostLogsRaw.map(normalizeLog);
    const securityRelevantLogs = recentTelemetryLogs.filter(isSecurityRelevantLog);
    const recentMlLogs = recentTelemetryLogs.filter((log) => Boolean(log?.metadata?.idsEngine?.is_anomaly));
    const recentHostAlerts = recentAlerts.filter((alert) =>
      ["rule-engine", "ids-engine-ml", "ids-engine"].includes(alert.source) &&
      /(process|file|privilege|host)/i.test(`${alert?.type || ""} ${alert?.attackType || ""}`)
    );

    return res.json({
      mode: recentTelemetryLogs.length > 0 || recentAlerts.length > 0 ? "live-monitoring" : "waiting-for-telemetry",
      alerts: {
        total: totalAlerts,
        critical: criticalAlerts,
        high: highAlerts,
        medium: mediumAlerts,
        low: lowAlerts,
        sourceDistribution: groupCounts(recentAlerts, (alert) => alert?.source || "unknown", 6),
        statusDistribution: groupCounts(recentAlerts, (alert) => alert?.status || "New", 6),
        severityDistribution: buildSeverityDistribution(allAlerts),
      },
      logs: {
        total: totalTelemetryLogs,
        snortTotal: totalLiveSnortLogs,
        hostTotal: totalHostLogs,
      },
      traffic: {
        eventsLast24h: recentTelemetryLogs.length,
        uniqueSourceIps: new Set(recentTelemetryLogs.map((log) => log?.derived?.srcIp).filter((value) => !isUnknownLike(value))).size,
        uniqueDestinationIps: new Set(recentTelemetryLogs.map((log) => log?.derived?.destIp).filter((value) => !isUnknownLike(value))).size,
        avgPriority: averageMetric(recentTelemetryLogs, (log) => log?.derived?.priority),
        liveSnortEventsLast24h: recentSnortLogs.length,
        hostEventsLast24h: recentHostLogs.length,
        liveSnortAlertsLast24h: recentAlerts.filter((alert) => alert.source === "snort").length,
        hostAlertsLast24h: recentHostAlerts.length,
        mlAnomaliesLast24h: recentMlLogs.length,
        sensorDistribution: groupCounts(recentTelemetryLogs, (log) => log?.metadata?.sensorType || log?.source || "unknown", 8),
        telemetryCoverage: buildTelemetryCoverage(recentTelemetryLogs),
      },
      analytics: {
        protocolDistribution: groupCounts(recentTelemetryLogs.filter(hasDerivedProtocol), (log) => log?.derived?.protocol, 6),
        topPorts: groupCounts(recentTelemetryLogs.filter(hasDerivedPort), (log) => log?.derived?.destPort, 8),
        topAttackTypes: groupCounts(allAlerts, (alert) => alert?.attackType || alert?.type || "Unknown", 5),
        classifications: groupCounts(recentAlerts, (alert) => alert?.attackType || alert?.type || "Unknown", 8),
        alertSourceDistribution: groupCounts(recentAlerts, (alert) => alert?.source || "unknown", 6),
        alertStatusDistribution: groupCounts(recentAlerts, (alert) => alert?.status || "New", 6),
        severityDistribution: buildSeverityDistribution(allAlerts),
        topSourceIps: buildIpCounts(allAlerts, securityRelevantLogs, (item) => item?.ip || item?.derived?.srcIp, 5),
        topDestinationIps: buildIpCounts(
          allAlerts,
          securityRelevantLogs,
          (item) => item?.metadata?.destinationIp || item?.metadata?.snort?.destIp || item?.derived?.destIp,
          5
        ),
        timeline: buildAlertTimelineBuckets(recentAlerts),
        recentLogs: securityRelevantLogs.slice(0, 12),
        recentAlerts: recentAlerts.slice(0, 8),
      },
      incidents: {
        open: openIncidents,
      },
      lastDetectionTime: latestAlert?.timestamp || securityRelevantLogs?.[0]?.timestamp || null,
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

    const liveSnortFilter = { ...orgFilter, ...buildSnortLogMatch() };
    const hostTelemetryFilter = { ...orgFilter, ...buildHostLogMatch() };

    const [lastAlert, lastSnortEvent, lastHostEvent, lastHeartbeat, liveSnortEventsLast24h, liveHostEventsLast24h, liveSnortEventsRecent, liveHostEventsRecent, recentOnlineAssets, recentHeartbeats] =
      await Promise.all([
        Alert.findOne(orgFilter).sort({ timestamp: -1 }),
        Log.findOne(liveSnortFilter).sort({ timestamp: -1 }),
        Log.findOne(hostTelemetryFilter).sort({ timestamp: -1 }),
        AgentHeartbeat.findOne(orgFilter).sort({ receivedAt: -1 }),
        Log.countDocuments({
          ...liveSnortFilter,
          timestamp: { $gte: new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000) },
        }),
        Log.countDocuments({
          ...hostTelemetryFilter,
          timestamp: { $gte: new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000) },
        }),
        Log.countDocuments({
          ...liveSnortFilter,
          timestamp: { $gte: new Date(Date.now() - LIVE_STATUS_WINDOW_MINS * 60 * 1000) },
        }),
        Log.countDocuments({
          ...hostTelemetryFilter,
          timestamp: { $gte: new Date(Date.now() - LIVE_STATUS_WINDOW_MINS * 60 * 1000) },
        }),
        Asset.countDocuments({
          ...orgFilter,
          agent_status: "online",
          agent_last_seen: { $gte: new Date(Date.now() - AGENT_STATUS_WINDOW_MINS * 60 * 1000) },
        }),
        AgentHeartbeat.countDocuments({
          ...orgFilter,
          receivedAt: { $gte: new Date(Date.now() - AGENT_STATUS_WINDOW_MINS * 60 * 1000) },
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
        message: idsEngine.message,
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
            telemetryTypes: Array.isArray(lastHeartbeat.telemetry_types) ? lastHeartbeat.telemetry_types : [],
            assetId: lastHeartbeat._asset_id?.toString?.() || null,
            metadata: lastHeartbeat.metadata || {},
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
            metadata: {},
          },
      snort: {
        status: snortStatus,
        lastEventAt: lastSnortEvent?.timestamp || null,
        liveEventsLast24h: liveSnortEventsLast24h,
        recentOnlineAssets,
        recentHeartbeats,
      },
      lastDetectionTime: lastAlert?.timestamp || lastHostEvent?.timestamp || lastSnortEvent?.timestamp || null,
    });
  } catch (error) {
    console.error("dashboard getHealth error:", error);
    return res.status(500).json({ message: "Failed to fetch health" });
  }
};

module.exports = { getStats, getHealth, getOverview };
