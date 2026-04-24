const { randomUUID } = require("crypto");
const axios = require("axios");

const config = require("../config/env");
const Alert = require("../models/Alerts");
const Asset = require("../models/Asset");
const Log = require("../models/Log");
const { upsertIncidentFromAlert } = require("./incident.service");

const IDS_TIMEOUT_MS = 5000;
const DEDUPE_WINDOW_MS = 10 * 60 * 1000;
const PORT_SCAN_WINDOW_MS = 5 * 60 * 1000;
const BRUTE_FORCE_WINDOW_MS = 10 * 60 * 1000;

const protocolCodes = {
  TCP: 1,
  UDP: 2,
  ICMP: 3,
  HTTP: 4,
  HTTPS: 5,
  SSH: 6,
  DNS: 7,
  FTP: 8,
  SMTP: 9,
  POP3: 10,
  IMAP: 11,
  TELNET: 12,
  RDP: 13,
  SMB: 14,
};

const severityProfiles = {
  Critical: { confidence: 0.95, riskScore: 92, weight: 55 },
  High: { confidence: 0.82, riskScore: 76, weight: 38 },
  Medium: { confidence: 0.64, riskScore: 58, weight: 22 },
  Low: { confidence: 0.42, riskScore: 34, weight: 10 },
};

const assetCriticalityWeights = {
  critical: 20,
  high: 15,
  medium: 10,
  low: 5,
};

const mapProtocol = (value) => protocolCodes[String(value || "").toUpperCase()] || 0;

const trimText = (value, fallback = "") => {
  const normalized = String(value ?? fallback).trim();
  return normalized;
};

const isMeaningful = (value) => {
  const normalized = trimText(value).toLowerCase();
  return Boolean(normalized) && normalized !== "unknown" && normalized !== "n/a" && normalized !== "-";
};

const safeNumber = (value, fallback = 0) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
};

const clampConfidence = (value, fallback = 0.5) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
};

const clampRiskScore = (value) => {
  const numeric = Math.round(safeNumber(value, 0));
  return Math.max(0, Math.min(100, numeric));
};

const normalizeSeverity = (value, fallback = "Medium") => {
  const normalized = trimText(value).toLowerCase();
  if (normalized === "critical") return "Critical";
  if (normalized === "high") return "High";
  if (normalized === "medium") return "Medium";
  if (normalized === "low") return "Low";
  return fallback;
};

const severityRank = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const maxSeverity = (current, incoming) =>
  (severityRank[incoming] || 0) > (severityRank[current] || 0) ? incoming : current;

const getTimestamp = (value) => {
  const parsed = new Date(value || Date.now());
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
};

const getMessageText = (log) =>
  trimText(
    log?.metadata?.snort?.message ||
      log?.metadata?.ids?.signature ||
      log?.metadata?.attackType ||
      log?.metadata?.normalized?.message ||
      log?.message
  ).toLowerCase();

const getProtocol = (log) =>
  trimText(
    log?.metadata?.normalized?.protocol ||
      log?.metadata?.protocol ||
      log?.metadata?.appProtocol ||
      log?.metadata?.snort?.protocol ||
      log?.metadata?.network?.protocol ||
      log?.protocol
  ).toUpperCase();

const getSourceIp = (log) =>
  trimText(
    log?.metadata?.normalized?.srcIp ||
      log?.metadata?.sourceIp ||
      log?.metadata?.network?.sourceIp ||
      log?.metadata?.snort?.srcIp ||
      log?.ip
  );

const getDestinationIp = (log) =>
  trimText(
    log?.metadata?.normalized?.destIp ||
      log?.metadata?.destinationIp ||
      log?.metadata?.network?.destinationIp ||
      log?.metadata?.snort?.destIp ||
      log?.destinationIp
  );

const getDestinationPort = (log) =>
  safeNumber(
    log?.metadata?.normalized?.port ??
      log?.metadata?.destinationPort ??
      log?.metadata?.port ??
      log?.metadata?.network?.destinationPort ??
      log?.metadata?.snort?.destPort ??
      log?.destinationPort,
    0
  );

const getRequestRate = (log) =>
  safeNumber(
    log?.metadata?.requestRate ??
      log?.metadata?.network?.requestRate ??
      log?.metadata?.request_rate,
    0
  );

const getPackets = (log) =>
  safeNumber(log?.metadata?.packets ?? log?.metadata?.network?.packets, 0);

const getBytes = (log) =>
  safeNumber(
    log?.metadata?.bytes ??
      log?.metadata?.network?.bytes ??
      log?.metadata?.outboundBytes ??
      log?.metadata?.network?.outboundBytes,
    0
  );

const getDnsQueries = (log) =>
  safeNumber(
    log?.metadata?.dnsQueries ??
      log?.metadata?.dns_queries ??
      log?.metadata?.network?.dnsQueries,
    0
  );

const getUserName = (log) =>
  trimText(
    log?.metadata?.host?.userName ||
      log?.metadata?.userName ||
      log?.metadata?.normalized?.userName ||
      log?.metadata?.username
  );

const getHostName = (log) =>
  trimText(
    log?.metadata?.host?.hostname ||
      log?.metadata?.hostname ||
      log?.metadata?.normalized?.hostname
  );

const getProcessName = (log) =>
  trimText(
    log?.metadata?.host?.processName ||
      log?.metadata?.processName ||
      log?.message
  ).toLowerCase();

const getCommandLine = (log) =>
  trimText(
    log?.metadata?.host?.commandLine ||
      log?.metadata?.commandLine
  ).toLowerCase();

const getFilePath = (log) =>
  trimText(
    log?.metadata?.host?.filePath ||
      log?.metadata?.filePath
  ).toLowerCase();

const getSensorType = (log) =>
  trimText(
    log?.metadata?.normalized?.sensorType ||
      log?.metadata?.sensorType ||
      log?.source
  ).toLowerCase();

const isIdsSensorLog = (log) => ["snort", "suricata", "nids"].includes(getSensorType(log));

const buildIdsHeaders = () => {
  if (!config.integrationApiKey) {
    return {};
  }

  return {
    "x-integration-api-key": config.integrationApiKey,
  };
};

const getRecommendedAction = (attackType) => {
  const normalized = trimText(attackType).toLowerCase();

  if (normalized.includes("port scan")) {
    return "Block or rate-limit the scanning source, review exposed services, and validate perimeter firewall rules.";
  }
  if (normalized.includes("ssh brute")) {
    return "Protect the targeted SSH service, enforce MFA and key-based auth, and block the attacking source IP.";
  }
  if (normalized.includes("web brute")) {
    return "Protect the affected login endpoint, enable rate limiting or CAPTCHA, and review impacted accounts.";
  }
  if (normalized.includes("ddos") || normalized.includes("dos") || normalized.includes("flood")) {
    return "Rate-limit traffic, engage upstream filtering, and inspect service saturation and network path health.";
  }
  if (normalized.includes("dns")) {
    return "Review resolver traffic, block suspicious domains or resolvers, and investigate possible tunneling.";
  }
  if (normalized.includes("exfiltration")) {
    return "Contain the asset, review outbound transfer destinations, and preserve evidence for incident response.";
  }
  if (normalized.includes("process")) {
    return "Isolate the endpoint, inspect process tree and command line, and collect endpoint forensic artifacts.";
  }
  if (normalized.includes("file integrity")) {
    return "Verify the changed file against baseline, review persistence indicators, and investigate local compromise.";
  }
  if (normalized.includes("privilege escalation")) {
    return "Review account activity, isolate the host, and investigate local privilege abuse or exploitation.";
  }

  return "Review correlated evidence, validate the alert, and escalate according to the incident response playbook.";
};

const mergeAlertMetadata = (current = {}, incoming = {}) => {
  const next = { ...current };

  Object.entries(incoming).forEach(([key, value]) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      next[key] = mergeAlertMetadata(current?.[key] || {}, value);
      return;
    }

    if (value !== undefined && value !== null && value !== "") {
      next[key] = value;
    }
  });

  return next;
};

const calculateRiskScore = async ({ log, severity, confidence, attackType }) => {
  const asset = log?._asset_id
    ? await Asset.findById(log._asset_id).select("asset_criticality")
    : null;

  const severityWeight = severityProfiles[severity]?.weight ?? severityProfiles.Medium.weight;
  const confidenceWeight = Math.round(clampConfidence(confidence, severityProfiles[severity]?.confidence ?? 0.5) * 25);
  const assetCriticalityWeight =
    assetCriticalityWeights[String(asset?.asset_criticality || "medium").toLowerCase()] ??
    assetCriticalityWeights.medium;

  const recentFrequency = await Alert.countDocuments({
    _org_id: log._org_id,
    attackType,
    ip: getSourceIp(log) || "unknown",
    timestamp: { $gte: new Date(Date.now() - BRUTE_FORCE_WINDOW_MS) },
  });

  const eventFrequencyWeight = Math.min(15, recentFrequency * 2);

  return clampRiskScore(severityWeight + confidenceWeight + eventFrequencyWeight + assetCriticalityWeight);
};

const buildAlertPayload = async ({
  log,
  type,
  attackType,
  severity,
  confidence,
  riskScore,
  source,
  relatedLogs = [],
  metadata = {},
  recommendedAction,
}) => {
  const normalizedSeverity = normalizeSeverity(severity);
  const resolvedConfidence = clampConfidence(
    confidence,
    severityProfiles[normalizedSeverity]?.confidence ?? severityProfiles.Medium.confidence
  );
  const resolvedRiskScore =
    riskScore ??
    (await calculateRiskScore({
      log,
      severity: normalizedSeverity,
      confidence: resolvedConfidence,
      attackType,
    }));

  return {
    type,
    attackType,
    severity: normalizedSeverity,
    status: "New",
    source,
    ip: getSourceIp(log) || "unknown",
    confidence: resolvedConfidence,
    risk_score: clampRiskScore(resolvedRiskScore),
    timestamp: log.timestamp || new Date(),
    relatedLogs: relatedLogs.length > 0 ? relatedLogs : [log._id],
    recommendedAction: recommendedAction || getRecommendedAction(attackType),
    metadata: {
      sensorType: getSensorType(log) || source,
      hostName: getHostName(log) || null,
      userName: getUserName(log) || null,
      sourceIp: getSourceIp(log) || null,
      destinationIp: getDestinationIp(log) || null,
      destinationPort: getDestinationPort(log) || null,
      protocol: getProtocol(log) || null,
      eventType: trimText(log?.eventType),
      ...(metadata || {}),
    },
  };
};

const findDuplicateAlert = async ({ orgId, type, ip, hostName }) =>
  Alert.findOne({
    _org_id: orgId,
    type,
    ip,
    ...(isMeaningful(hostName) ? { "metadata.hostName": hostName } : {}),
    timestamp: { $gte: new Date(Date.now() - DEDUPE_WINDOW_MS) },
    status: { $ne: "Resolved" },
  }).sort({ timestamp: -1 });

const createDetectionAlert = async ({
  log,
  attackType,
  type = attackType,
  severity,
  confidence,
  risk_score,
  source = "rule-engine",
  relatedLogs = [],
  metadata = {},
  recommendedAction,
}) => {
  const payload = await buildAlertPayload({
    log,
    type,
    attackType,
    severity,
    confidence,
    riskScore: risk_score,
    source,
    relatedLogs,
    metadata,
    recommendedAction: recommendedAction || getRecommendedAction(attackType),
  });

  const duplicate = await findDuplicateAlert({
    orgId: log._org_id,
    type: payload.type,
    ip: payload.ip,
    hostName: payload.metadata.hostName,
  });

  if (duplicate) {
    duplicate.severity = maxSeverity(duplicate.severity, payload.severity);
    duplicate.confidence = Math.max(Number(duplicate.confidence || 0), Number(payload.confidence || 0));
    duplicate.risk_score = Math.max(Number(duplicate.risk_score || 0), Number(payload.risk_score || 0));
    duplicate.relatedLogs = [
      ...new Set(
        [...(duplicate.relatedLogs || []).map((value) => value.toString()), ...payload.relatedLogs.map((value) => value.toString())]
      ),
    ];
    duplicate.recommendedAction = payload.recommendedAction;
    duplicate.metadata = mergeAlertMetadata(duplicate.metadata || {}, payload.metadata || {});
    duplicate.markModified("metadata");
    await duplicate.save();
    await upsertIncidentFromAlert(duplicate);
    return duplicate;
  }

  const alert = await Alert.create({
    _org_id: log._org_id,
    _asset_id: log._asset_id,
    ...payload,
    alertId: trimText(log?.eventId || log?._id || randomUUID()),
  });

  await upsertIncidentFromAlert(alert);
  return alert;
};

const buildSampleFromLog = (log) => {
  const protocol = getProtocol(log);
  const destinationPort = getDestinationPort(log);

  return {
    event_id: log.eventId || log._id?.toString?.(),
    source: log.source,
    event_type: log.eventType,
    message: log.message,
    ip: getSourceIp(log),
    destination_ip: getDestinationIp(log),
    destination_port: destinationPort,
    protocol,
    protocol_code: mapProtocol(protocol),
    request_rate: getRequestRate(log),
    packets: getPackets(log),
    bytes: getBytes(log),
    failed_attempts: safeNumber(
      log?.metadata?.failedAttempts ??
        log?.metadata?.host?.failedAttempts,
      0
    ),
    flow_count: safeNumber(log?.metadata?.flowCount ?? log?.metadata?.network?.flowCount, 0),
    unique_ports: safeNumber(log?.metadata?.uniquePorts, 0),
    dns_queries: getDnsQueries(log),
    smb_writes: safeNumber(log?.metadata?.smbWrites ?? log?.metadata?.smb_writes, 0),
    duration: safeNumber(log?.metadata?.duration, 0),
    snort_priority: safeNumber(log?.metadata?.snort?.priority, 0),
    is_snort: isIdsSensorLog(log) ? 1 : 0,
    timestamp: log.timestamp ? new Date(log.timestamp).toISOString() : new Date().toISOString(),
    metadata: {
      classification: trimText(log?.metadata?.snort?.classification),
      signature_id: log?.metadata?.snort?.signatureId || null,
      generator_id: log?.metadata?.snort?.generatorId || null,
      host_name: getHostName(log) || null,
      user_name: getUserName(log) || null,
    },
  };
};

const rulePortScan = async (log) => {
  const srcIp = getSourceIp(log);
  if (!isMeaningful(srcIp)) return null;

  const recentLogs = await Log.find({
    _org_id: log._org_id,
    $or: [
      { ip: srcIp },
      { "metadata.sourceIp": srcIp },
      { "metadata.snort.srcIp": srcIp },
      { "metadata.normalized.srcIp": srcIp },
    ],
    timestamp: { $gte: new Date(Date.now() - PORT_SCAN_WINDOW_MS) },
  }).select("metadata");

  const uniquePorts = new Set();
  recentLogs.forEach((entry) => {
    const port = safeNumber(
      entry?.metadata?.normalized?.port ??
        entry?.metadata?.destinationPort ??
        entry?.metadata?.port ??
        entry?.metadata?.snort?.destPort,
      0
    );
    if (port > 0) uniquePorts.add(port);
  });

  if (uniquePorts.size < 10) return null;

  return createDetectionAlert({
    log,
    type: "Port Scan",
    attackType: "Port Scan",
    severity: "High",
    source: "rule-engine",
    metadata: {
      family: "port-scan",
      uniquePorts: uniquePorts.size,
    },
  });
};

const ruleSshBruteForce = async (log) => {
  const srcIp = getSourceIp(log);
  const port = getDestinationPort(log);
  const eventType = trimText(log?.eventType).toLowerCase();
  const failed =
    eventType === "auth.failure" ||
    log?.metadata?.success === false ||
    log?.metadata?.host?.loginSuccess === false ||
    getMessageText(log).includes("failed");

  if (!failed || (!srcIp && port !== 22 && eventType !== "auth.failure")) return null;
  if (port !== 22 && eventType !== "auth.failure" && !getMessageText(log).includes("ssh")) return null;

  const sshSourceMatchers = isMeaningful(srcIp)
    ? [
        { ip: srcIp },
        { "metadata.sourceIp": srcIp },
        { "metadata.snort.srcIp": srcIp },
        { "metadata.normalized.srcIp": srcIp },
      ]
    : [];

  const count = await Log.countDocuments({
    _org_id: log._org_id,
    timestamp: { $gte: new Date(Date.now() - BRUTE_FORCE_WINDOW_MS) },
    $and: [
      sshSourceMatchers.length > 0 ? { $or: sshSourceMatchers } : {},
      {
        $or: [
          { eventType: "auth.failure" },
          { "metadata.success": false },
          { "metadata.host.loginSuccess": false },
          { "metadata.destinationPort": 22 },
          { "metadata.port": 22 },
          { "metadata.snort.destPort": 22 },
          { "metadata.normalized.port": 22 },
        ],
      },
    ],
  });

  if (count < 5) return null;

  return createDetectionAlert({
    log,
    type: "SSH Brute Force",
    attackType: "SSH Brute Force",
    severity: "High",
    source: "rule-engine",
    metadata: {
      family: "ssh-brute-force",
      failureCount: count,
      destinationPort: port || 22,
    },
  });
};

const ruleWebBruteForce = async (log) => {
  const port = getDestinationPort(log);
  const endpoint = trimText(log?.endpoint || log?.metadata?.endpoint).toLowerCase();
  const failedAttempts = safeNumber(log?.metadata?.failedAttempts ?? log?.metadata?.host?.failedAttempts, 0);
  const requestRate = getRequestRate(log);
  const srcIp = getSourceIp(log);

  const looksLikeWebAuth = [80, 443, 8080, 8443, 3000, 5000].includes(port) || endpoint.includes("login") || endpoint.includes("signin");
  if (!looksLikeWebAuth) return null;

  const recentFailureCount = await Log.countDocuments({
    _org_id: log._org_id,
    timestamp: { $gte: new Date(Date.now() - BRUTE_FORCE_WINDOW_MS) },
    ...(isMeaningful(srcIp)
      ? {
          $or: [
            { ip: srcIp },
            { "metadata.sourceIp": srcIp },
            { "metadata.normalized.srcIp": srcIp },
          ],
        }
      : {}),
    $or: [
      { eventType: "auth.failure" },
      { "metadata.failedAttempts": { $gte: 1 } },
      { "metadata.host.loginSuccess": false },
    ],
  });

  if (Math.max(failedAttempts, recentFailureCount) < 5 && requestRate < 60) return null;

  return createDetectionAlert({
    log,
    type: "Web Brute Force",
    attackType: "Web Brute Force",
    severity: "High",
    source: "rule-engine",
    metadata: {
      family: "web-brute-force",
      failureCount: Math.max(failedAttempts, recentFailureCount),
      requestRate,
      destinationPort: port,
      endpoint,
    },
  });
};

const ruleDos = async (log) => {
  const requestRate = getRequestRate(log);
  const packets = getPackets(log);
  if (requestRate <= 150 && packets <= 1000) return null;

  return createDetectionAlert({
    log,
    type: "DDoS / DoS",
    attackType: "DDoS / DoS",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      family: "ddos",
      requestRate,
      packets,
    },
  });
};

const ruleIcmpFlood = async (log) => {
  const protocol = getProtocol(log);
  const requestRate = getRequestRate(log);
  if (protocol !== "ICMP" || requestRate <= 80) return null;

  return createDetectionAlert({
    log,
    type: "ICMP Flood",
    attackType: "ICMP Flood",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      family: "icmp-flood",
      requestRate,
      protocol,
    },
  });
};

const ruleDnsAbuse = async (log) => {
  const protocol = getProtocol(log);
  const port = getDestinationPort(log);
  const dnsQueries = getDnsQueries(log);
  const requestRate = getRequestRate(log);
  if (protocol !== "UDP" || port !== 53 || (dnsQueries < 60 && requestRate < 80)) return null;

  return createDetectionAlert({
    log,
    type: "DNS Abuse",
    attackType: "DNS Abuse",
    severity: "High",
    source: "rule-engine",
    metadata: {
      family: "dns-abuse",
      dnsQueries,
      requestRate,
      destinationPort: port,
    },
  });
};

const ruleDataExfiltration = async (log) => {
  const bytes = getBytes(log);
  if (bytes <= 104857600) return null;

  return createDetectionAlert({
    log,
    type: "Data Exfiltration",
    attackType: "Data Exfiltration",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      family: "data-exfiltration",
      bytes,
      destinationIp: getDestinationIp(log) || null,
    },
  });
};

const ruleSuspiciousProcess = async (log) => {
  const processName = getProcessName(log);
  const commandLine = getCommandLine(log);
  const haystack = `${processName} ${commandLine}`.toLowerCase();
  const patterns = ["powershell", "wmic", "encodedcommand", "rundll32", "regsvr32"];
  if (!patterns.some((pattern) => haystack.includes(pattern))) return null;

  return createDetectionAlert({
    log,
    type: "Suspicious Process Execution",
    attackType: "Suspicious Process Execution",
    severity: "High",
    source: "rule-engine",
    metadata: {
      family: "suspicious-process",
      processName,
      commandLine,
    },
  });
};

const ruleFileIntegrityChange = async (log) => {
  const eventType = trimText(log?.eventType).toLowerCase();
  const filePath = getFilePath(log);
  const sensitiveMarkers = [
    "system32",
    "\\startup",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    ".ssh",
    "authorized_keys",
    "windows\\tasks",
    "cron",
  ];

  if (eventType !== "file.change" && !getMessageText(log).includes("file")) return null;
  if (!sensitiveMarkers.some((marker) => filePath.includes(marker))) return null;

  return createDetectionAlert({
    log,
    type: "File Integrity Change",
    attackType: "File Integrity Change",
    severity: "High",
    source: "rule-engine",
    metadata: {
      family: "file-integrity",
      filePath,
      action: trimText(log?.metadata?.host?.action || log?.metadata?.action),
    },
  });
};

const rulePrivilegeEscalation = async (log) => {
  const eventType = trimText(log?.eventType).toLowerCase();
  const message = getMessageText(log);
  const elevated = Boolean(log?.metadata?.host?.elevated);

  if (
    !elevated &&
    eventType !== "privilege.escalation" &&
    !/(sudo|administrator|admin token|root|escalat)/i.test(message)
  ) {
    return null;
  }

  return createDetectionAlert({
    log,
    type: "Privilege Escalation",
    attackType: "Privilege Escalation",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      family: "privilege-escalation",
      userName: getUserName(log) || null,
      processName: getProcessName(log) || null,
    },
  });
};

const evaluateRuleDetections = async (log) => {
  const rules = [
    rulePortScan,
    ruleSshBruteForce,
    ruleWebBruteForce,
    ruleDos,
    ruleIcmpFlood,
    ruleDnsAbuse,
    ruleDataExfiltration,
    ruleSuspiciousProcess,
    ruleFileIntegrityChange,
    rulePrivilegeEscalation,
  ];

  const results = [];
  for (const rule of rules) {
    const detection = await rule(log);
    if (detection) {
      results.push(detection);
    }
  }
  return results;
};

const applyIdsResults = async (logs, results = []) => {
  const resultsByEventId = new Map(
    results
      .filter((item) => item && item.event_id)
      .map((item) => [item.event_id, item])
  );

  const updates = [];
  const anomalyAlerts = [];

  logs.forEach((log) => {
    const eventId = log.eventId || log._id?.toString?.();
    const result = resultsByEventId.get(eventId);

    if (!result) {
      return;
    }

    updates.push({
      updateOne: {
        filter: { _id: log._id },
        update: {
          $set: {
            "metadata.idsEngine": {
              analyzed_at: new Date(),
              algorithm: result.analysis?.algorithm || null,
              score: result.analysis?.score ?? null,
              confidence: result.analysis?.confidence ?? null,
              threshold: result.analysis?.threshold ?? null,
              is_anomaly: Boolean(result.analysis?.is_anomaly),
              severity: result.analysis?.severity || null,
              using_fallback: Boolean(result.analysis?.using_fallback),
              reason: result.analysis?.reason || null,
              submodels: result.analysis?.submodels || null,
            },
          },
        },
      },
    });

    if (result.analysis?.is_anomaly) {
      anomalyAlerts.push(
        createDetectionAlert({
          log,
          type: "ML Detection",
          attackType:
            result.analysis?.submodels?.random_forest?.predicted_class ||
            (isIdsSensorLog(log) ? "ML IDS Anomaly" : "ML Behavioral Anomaly"),
          severity: normalizeSeverity(result.analysis?.severity, "Medium"),
          confidence: result.analysis?.confidence,
          risk_score: result.analysis?.risk_score,
          source: "ids-engine-ml",
          metadata: {
            family: "ml-anomaly",
            algorithm: result.analysis?.algorithm || null,
            reason: result.analysis?.reason || null,
            score: result.analysis?.score ?? null,
            threshold: result.analysis?.threshold ?? null,
            usingFallback: Boolean(result.analysis?.using_fallback),
            predictedClass:
              result.analysis?.submodels?.random_forest?.predicted_class || null,
          },
        })
      );
    }
  });

  if (updates.length > 0) {
    await Log.bulkWrite(updates, { ordered: false });
  }

  if (anomalyAlerts.length > 0) {
    await Promise.all(anomalyAlerts);
  }
};

const getIdsEngineHealth = async () => {
  if (!config.enableIdsAnalysis) {
    return {
      status: "disabled",
      message: "IDS engine analysis disabled",
      reachable: false,
      modelLoaded: null,
      algorithm: null,
      usingFallback: true,
    };
  }

  try {
    const response = await axios.get(`${config.idsEngineUrl}/health`, {
      timeout: 3000,
      headers: buildIdsHeaders(),
    });

    const data = response.data || {};
    const normalizedStatus =
      String(data.status || "").toLowerCase() === "ok" ? "online" : data.status || "online";
    const modelInfo = data.model && typeof data.model === "object" ? data.model : null;

    return {
      status: normalizedStatus,
      reachable: true,
      message: data.message || "IDS engine reachable",
      modelLoaded:
        modelInfo && modelInfo.loaded !== undefined ? Boolean(modelInfo.loaded) : null,
      algorithm: modelInfo?.algorithm || null,
      trainedAt: modelInfo?.trained_at || null,
      usingFallback:
        modelInfo && modelInfo.using_fallback !== undefined
          ? Boolean(modelInfo.using_fallback)
          : null,
      featureNames: Array.isArray(modelInfo?.feature_names) ? modelInfo.feature_names : [],
      rfModel: modelInfo?.rf_model || null,
      svmModel: modelInfo?.svm_model || null,
      legacyModel: modelInfo?.legacy_model || null,
      error: modelInfo?.error || null,
      details: data,
    };
  } catch (error) {
    return {
      status: "offline",
      reachable: false,
      message: error.message,
      modelLoaded: null,
      algorithm: null,
      usingFallback: null,
      error: error.response?.data?.message || null,
    };
  }
};

const analyzeLogs = async (logs = []) => {
  if (logs.length === 0) {
    return { status: "skipped", analyzed: 0, results: [], detections: 0 };
  }

  let detections = 0;
  for (const log of logs) {
    const matched = await evaluateRuleDetections(log);
    detections += matched.length;
  }

  if (!config.enableIdsAnalysis) {
    return { status: "rules-only", analyzed: 0, results: [], detections };
  }

  const events = logs.map(buildSampleFromLog);

  try {
    const response = await axios.post(
      `${config.idsEngineUrl}/analyze`,
      { events },
      {
        timeout: IDS_TIMEOUT_MS,
        headers: {
          "Content-Type": "application/json",
          ...buildIdsHeaders(),
        },
      }
    );

    const payload = response.data || {};
    const results = Array.isArray(payload.results) ? payload.results : [];
    await applyIdsResults(logs, results);

    return {
      status: payload.status || "ok",
      analyzed: results.length,
      model: payload.model || null,
      results,
      detections,
    };
  } catch (error) {
    return {
      status: "offline",
      analyzed: 0,
      results: [],
      detections,
      error: error.message,
    };
  }
};

module.exports = {
  analyzeLogs,
  buildSampleFromLog,
  createDetectionAlert,
  getIdsEngineHealth,
};
