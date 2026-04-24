const Log = require("../models/Log");
const Alert = require("../models/Alerts");
const Asset = require("../models/Asset");
const config = require("../config/env");
const { upsertCorrelatedAlert } = require("./alert.service");

const severityProfiles = {
  Critical: { confidence: 0.95, riskScore: 92 },
  High: { confidence: 0.82, riskScore: 76 },
  Medium: { confidence: 0.64, riskScore: 58 },
  Low: { confidence: 0.42, riskScore: 34 },
};

const telemetryWindowStart = () =>
  new Date(Date.now() - config.alertCorrelationWindowMins * 60 * 1000);

const TELEMETRY_SOURCES = new Set(["agent", "upload", "ids-engine", "snort", "suricata", "request"]);

const isTelemetryLog = (log) => TELEMETRY_SOURCES.has(log.source);
const WEB_PORTS = new Set([80, 443, 3000, 5000, 8000, 8080, 8443]);

const normalizeTelemetryValue = (value) => {
  if (value === null || value === undefined) return null;
  const normalized = String(value).trim();
  if (!normalized) return null;

  const lower = normalized.toLowerCase();
  if (lower === "unknown" || lower === "n/a" || lower === "-") {
    return null;
  }

  return normalized;
};

const getMessageText = (log) =>
  String(
    log?.metadata?.snort?.message ||
      log?.metadata?.ids?.signature ||
      log?.metadata?.attackType ||
      log?.message ||
      ""
  ).toLowerCase();

const getDestinationPort = (log) =>
  Number(
    log?.metadata?.snort?.destPort ??
      log?.metadata?.destinationPort ??
      log?.metadata?.port ??
      0
  );

const getProtocol = (log) =>
  String(
    log?.metadata?.protocol ||
      log?.metadata?.appProtocol ||
      log?.metadata?.snort?.protocol ||
      ""
  ).toUpperCase();

const getEndpointText = (log) =>
  String(log?.endpoint || log?.metadata?.endpoint || "").toLowerCase();

const includesAny = (value, patterns = []) => patterns.some((pattern) => value.includes(pattern));
const getSensorType = (log) =>
  String(log?.metadata?.sensorType || log?.source || "")
    .trim()
    .toLowerCase();

const severityWeightMap = {
  Critical: 55,
  High: 38,
  Medium: 22,
  Low: 10,
};

const assetCriticalityWeightMap = {
  critical: 20,
  high: 15,
  medium: 10,
  low: 5,
};

const normalizeConfidence = (value, severity = "Medium") => {
  const candidate = Number(value);
  if (Number.isFinite(candidate)) {
    return Math.max(0, Math.min(1, candidate));
  }

  return severityProfiles[severity]?.confidence ?? severityProfiles.Medium.confidence;
};

const clampRiskScore = (value) => {
  const score = Math.round(Number(value) || 0);
  return Math.max(0, Math.min(100, score));
};

const getRecommendedAction = (attackType) => {
  const normalized = String(attackType || "").toLowerCase();

  if (normalized.includes("ddos") || normalized.includes("flood")) {
    return "Rate-limit or block the offending source, verify upstream filtering, and inspect affected services.";
  }
  if (normalized.includes("port scan")) {
    return "Block or monitor the scanning source, review exposed services, and validate firewall posture.";
  }
  if (normalized.includes("ssh brute") || normalized.includes("web brute")) {
    return "Lock or protect the targeted account/service, enforce MFA, and block the attacking source.";
  }
  if (normalized.includes("dns")) {
    return "Inspect DNS destinations, block suspicious resolvers/domains, and review egress policy.";
  }
  if (normalized.includes("exfiltration")) {
    return "Contain the affected asset, inspect outbound transfers, and preserve evidence for incident response.";
  }
  if (normalized.includes("process")) {
    return "Isolate the endpoint, review the spawned process tree and command line, and collect host forensics.";
  }
  if (normalized.includes("file integrity")) {
    return "Validate the file modification, compare against baseline, and check for persistence or tampering.";
  }
  if (normalized.includes("privilege escalation")) {
    return "Review account activity, isolate the host, and investigate for credential abuse or local exploitation.";
  }

  return "Review correlated evidence, validate the detection, and escalate according to the incident playbook.";
};

const buildAlertMetadataFromLog = (log, metadata = {}) => {
  const snort = log?.metadata?.snort || {};
  const protocol =
    normalizeTelemetryValue(log?.metadata?.protocol) ||
    normalizeTelemetryValue(log?.metadata?.appProtocol) ||
    normalizeTelemetryValue(snort?.protocol);

  const sourceIp =
    normalizeTelemetryValue(snort?.srcIp) ||
    normalizeTelemetryValue(log?.ip) ||
    normalizeTelemetryValue(log?.metadata?.sourceIp);

  const destinationIp =
    normalizeTelemetryValue(snort?.destIp) ||
    normalizeTelemetryValue(log?.metadata?.destinationIp);

  const destinationPort =
    snort?.destPort ??
    log?.metadata?.destinationPort ??
    log?.metadata?.port ??
    null;

  const classification =
    normalizeTelemetryValue(snort?.classification) ||
    normalizeTelemetryValue(log?.metadata?.classification);

  const priority = snort?.priority ?? log?.priority ?? null;

  return {
    ...metadata,
    protocol: protocol || metadata?.protocol || null,
    sourceIp: sourceIp || metadata?.sourceIp || null,
    destinationIp: destinationIp || metadata?.destinationIp || null,
    destinationPort:
      destinationPort !== null && destinationPort !== undefined
        ? Number(destinationPort)
        : metadata?.destinationPort ?? null,
    classification: classification || metadata?.classification || null,
    priority: priority !== null && priority !== undefined ? Number(priority) : metadata?.priority ?? null
  };
};

const getAssetCriticalityWeight = async (assetId) => {
  if (!assetId) return assetCriticalityWeightMap.medium;

  const asset = await Asset.findById(assetId).select("asset_criticality");
  const criticality = String(asset?.asset_criticality || "medium").toLowerCase();
  return assetCriticalityWeightMap[criticality] || assetCriticalityWeightMap.medium;
};

const getEventFrequencyWeight = async (log, attackType) => {
  const sourceIp = log.ip || log?.metadata?.sourceIp || log?.metadata?.snort?.srcIp || null;
  const relatedAlertCount = await Alert.countDocuments({
    _org_id: log._org_id,
    attackType,
    ...(sourceIp ? { ip: sourceIp } : {}),
    timestamp: { $gte: telemetryWindowStart() },
    status: { $ne: "Resolved" },
  });

  const relatedLogCount = await Log.countDocuments({
    _org_id: log._org_id,
    ...(sourceIp ? { ip: sourceIp } : {}),
    timestamp: { $gte: telemetryWindowStart() },
  });

  return Math.min(15, relatedAlertCount * 2 + Math.min(relatedLogCount, 7));
};

const calculateRiskScore = async ({ log, severity, confidence, attackType }) => {
  const normalizedSeverity = severityProfiles[severity] ? severity : "Medium";
  const severityWeight = severityWeightMap[normalizedSeverity] || severityWeightMap.Medium;
  const confidenceWeight = Math.round(normalizeConfidence(confidence, normalizedSeverity) * 25);
  const eventFrequencyWeight = await getEventFrequencyWeight(log, attackType);
  const assetCriticalityWeight = await getAssetCriticalityWeight(log?._asset_id);

  return clampRiskScore(
    severityWeight + confidenceWeight + eventFrequencyWeight + assetCriticalityWeight
  );
};

const createDetectionAlert = async ({
  log,
  attackType,
  type = attackType,
  severity,
  confidence,
  risk_score,
  source = "ids-engine",
  metadata = {},
}) => {
  const normalizedSeverity = severityProfiles[severity] ? severity : "Medium";
  const normalizedConfidence = normalizeConfidence(confidence, normalizedSeverity);
  const computedRiskScore = await calculateRiskScore({
    log,
    severity: normalizedSeverity,
    confidence: normalizedConfidence,
    attackType,
  });

  return upsertCorrelatedAlert({
    orgId: log._org_id,
    assetId: log._asset_id,
    attackType,
    type,
    ip: log.ip || log.metadata?.snort?.srcIp || "unknown",
    severity: normalizedSeverity,
    confidence: normalizedConfidence,
    risk_score: risk_score ?? computedRiskScore,
    relatedLogs: [log._id],
    source,
    metadata: buildAlertMetadataFromLog(log, {
      ...metadata,
      recommendedAction: metadata?.recommendedAction || getRecommendedAction(attackType),
      riskModel: {
        severityWeight: severityWeightMap[normalizedSeverity] || severityWeightMap.Medium,
        confidence: normalizedConfidence,
      },
    }),
  });
};

const evaluateBruteForce = async (log) => {
  if (!isTelemetryLog(log) || log.eventType !== "auth.login" || log.metadata?.success !== false) {
    return null;
  }

  const failures = await Log.countDocuments({
    _org_id: log._org_id,
    eventType: "auth.login",
    ip: log.ip,
    "metadata.success": false,
    timestamp: { $gte: telemetryWindowStart() },
  });

  if (failures < config.bruteforceThreshold) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "SSH Brute Force",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "authentication",
      family: "ssh-brute-force",
      destinationPort: getDestinationPort(log),
      failedAttempts: failures,
    },
  });
};

const evaluateSqlInjection = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const message = getMessageText(log);
  const endpoint = getEndpointText(log);
  const destinationPort = getDestinationPort(log);

  if (
    !includesAny(message, ["sql injection", "union select", "sqli", "database error", "sqlmap"]) &&
    !includesAny(endpoint, ["select", "union", " or 1=1", "information_schema"])
  ) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "SQL Injection Attempt",
    severity: WEB_PORTS.has(destinationPort) ? "High" : "Medium",
    source: "rule-engine",
    metadata: {
      category: "vulnerability",
      family: "web-exploitation",
      destinationPort
    }
  });
};

const evaluateXss = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const message = getMessageText(log);
  const endpoint = getEndpointText(log);
  if (
    !includesAny(message, ["xss", "cross-site scripting", "<script", "javascript:"]) &&
    !includesAny(endpoint, ["<script", "javascript:", "onerror=", "onload="])
  ) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Cross-Site Scripting Attempt",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "vulnerability",
      family: "web-exploitation"
    }
  });
};

const evaluateDirectoryTraversal = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const message = getMessageText(log);
  const endpoint = getEndpointText(log);
  if (
    !includesAny(message, ["directory traversal", "path traversal", "../", "..\\"]) &&
    !includesAny(endpoint, ["../", "..\\", "/etc/passwd", "win.ini"])
  ) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Directory Traversal Attempt",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "vulnerability",
      family: "path-traversal"
    }
  });
};

const evaluateRemoteCodeExecution = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const message = getMessageText(log);
  const endpoint = getEndpointText(log);
  if (
    !includesAny(message, [
      "remote code execution",
      "rce",
      "command injection",
      "shellshock",
      "log4shell",
      "deserialization",
      "web shell"
    ]) &&
    !includesAny(endpoint, ["cmd=", "powershell", "/bin/sh", "wget ", "curl "])
  ) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Remote Code Execution Attempt",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      category: "vulnerability",
      family: "rce"
    }
  });
};

const evaluateVulnerabilityProbe = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const message = getMessageText(log);
  if (!includesAny(message, ["cve-", "vulnerability", "exploit kit", "metasploit", "nuclei", "nikto", "nessus"])) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Vulnerability Exploitation Attempt",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "vulnerability",
      family: "scanner-or-exploit"
    }
  });
};

const evaluateDnsTunneling = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const protocol = getProtocol(log);
  const destinationPort = getDestinationPort(log);
  const dnsQueries = Number(log?.metadata?.dnsQueries || log?.metadata?.dns_queries || 0);
  const message = getMessageText(log);

  if (
    !(protocol === "UDP" || protocol === "DNS" || destinationPort === 53) &&
    !message.includes("dns")
  ) {
    return null;
  }

  if (dnsQueries < 60 && !includesAny(message, ["dns tunneling", "dns tunnel", "suspicious dns"])) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "DNS Abuse",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "threat",
      family: "dns-tunneling",
      dnsQueries
    }
  });
};

const evaluateMalwareBeaconing = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const message = getMessageText(log);
  const flowCount = Number(log?.metadata?.flowCount || 0);
  const bytes = Number(log?.metadata?.bytes || 0);

  if (
    !includesAny(message, ["beacon", "trojan", "malware", "c2", "command and control"]) &&
    !(flowCount >= 10 && bytes >= 15000 && ["snort", "suricata"].includes(getSensorType(log)))
  ) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Malware Beaconing / C2 Activity",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      category: "threat",
      family: "malware-c2"
    }
  });
};

const evaluatePrivilegedServiceExposure = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const destinationPort = getDestinationPort(log);
  const message = getMessageText(log);
  const sensitivePorts = new Set([21, 22, 23, 3389, 5432, 3306, 6379, 9200]);

  if (!sensitivePorts.has(destinationPort) && !includesAny(message, ["telnet", "rdp", "exposed database", "anonymous login"])) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Sensitive Service Exposure",
    severity: destinationPort === 23 || destinationPort === 6379 ? "Critical" : "High",
    source: "rule-engine",
    metadata: {
      category: "vulnerability",
      family: "exposed-service",
      destinationPort
    }
  });
};

const evaluateUnauthorizedAdminAccess = async (log) => {
  if (log.eventType !== "authz.denied") {
    return null;
  }

  const requiredRoles = log.metadata?.requiredRoles || [];
  if (!requiredRoles.includes("admin")) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Unauthorized Admin Access",
    severity: "Critical",
    source: "rule-engine",
  });
};

const evaluateSuspiciousProcessCreation = async (log) => {
  if (log.eventType !== "process.start") {
    return null;
  }

  const processName = String(
    log?.metadata?.host?.processName ||
      log?.metadata?.processName ||
      log?.message ||
      ""
  ).toLowerCase();

  const suspiciousPatterns = [
    "powershell",
    "cmd.exe",
    "wmic",
    "rundll32",
    "regsvr32",
    "mimikatz",
    "psexec",
    "/bin/sh",
    "/bin/bash",
    "nc ",
    "ncat",
  ];

  if (!includesAny(processName, suspiciousPatterns)) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Suspicious Process",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "host",
      family: "process-execution",
      processName: log?.metadata?.host?.processName || log?.metadata?.processName || null,
      commandLine: log?.metadata?.host?.commandLine || null,
    },
  });
};

const evaluateSensitiveFileChange = async (log) => {
  if (log.eventType !== "file.change") {
    return null;
  }

  const filePath = String(
    log?.metadata?.host?.filePath || log?.metadata?.filePath || ""
  ).toLowerCase();

  if (
    !includesAny(filePath, [
      "system32",
      "\\startup",
      "/etc/passwd",
      "/etc/shadow",
      "/etc/sudoers",
      ".ssh",
      "authorized_keys",
      "windows\\tasks",
      "cron",
    ])
  ) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "File Integrity Change",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "host",
      family: "file-integrity",
      filePath: log?.metadata?.host?.filePath || log?.metadata?.filePath || null,
      action: log?.metadata?.host?.action || log?.metadata?.action || null,
    },
  });
};

const evaluatePrivilegeEscalation = async (log) => {
  const elevated =
    Boolean(log?.metadata?.host?.elevated) ||
    log.eventType === "privilege.escalation";

  if (!elevated) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Privilege Escalation Indicator",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      category: "host",
      family: "privilege-escalation",
      userName: log?.metadata?.host?.userName || null,
      processName: log?.metadata?.host?.processName || null,
    },
  });
};

const evaluatePersistenceChange = async (log) => {
  if (!["service.change", "startup.persistence"].includes(log.eventType)) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Persistence / Service Modification",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "host",
      family: "persistence",
      serviceName: log?.metadata?.host?.serviceName || null,
      startupEntry: log?.metadata?.host?.startupEntry || null,
    },
  });
};

const evaluateHostLoginFailures = async (log) => {
  if (log.eventType !== "auth.login" || log?.metadata?.host?.loginSuccess !== false) {
    return null;
  }

  const userName = log?.metadata?.host?.userName || null;

  const failures = await Log.countDocuments({
    _org_id: log._org_id,
    eventType: "auth.login",
    "metadata.host.loginSuccess": false,
    ...(userName ? { "metadata.host.userName": userName } : {}),
    timestamp: { $gte: telemetryWindowStart() },
  });

  if (failures < config.bruteforceThreshold) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Host Authentication Brute Force",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "host",
      family: "authentication",
      userName,
      failureCount: failures,
    },
  });
};

const evaluateDosBurst = async (log) => {
  if (!isTelemetryLog(log) || log.eventType !== "request") {
    return null;
  }

  const count = await Log.countDocuments({
    _org_id: log._org_id,
    eventType: "request",
    ip: log.ip,
    timestamp: { $gte: new Date(Date.now() - 60 * 1000) },
  });

  if (count < config.dosThresholdPerMinute) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "DDoS / Request Flood",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      category: "network",
      family: "ddos",
      requestRate: count,
    },
  });
};

const evaluateSuspiciousIp = async (log) => {
  if (!isTelemetryLog(log) || !log.ip) {
    return null;
  }

  const distinctEndpoints = await Log.distinct("endpoint", {
    _org_id: log._org_id,
    ip: log.ip,
    timestamp: { $gte: telemetryWindowStart() },
  });

  if (distinctEndpoints.length < 10) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Suspicious IP Activity",
    severity: "Medium",
    source: "rule-engine",
  });
};

const evaluatePortScan = async (log) => {
  if (!isTelemetryLog(log) || !log.ip) {
    return null;
  }

  const destinations = await Log.distinct("metadata.destinationPort", {
    _org_id: log._org_id,
    ip: log.ip,
    timestamp: { $gte: telemetryWindowStart() },
  });

  const uniquePorts = destinations.filter((value) => value !== null && value !== undefined);
  if (uniquePorts.length < 10) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Port Scan Activity",
    severity: "High",
    source: "rule-engine",
    metadata: {
      category: "network",
      family: "port-scan",
      uniquePorts: uniquePorts.length,
    },
  });
};

const evaluateCredentialStuffing = async (log) => {
  if (!isTelemetryLog(log) || log.eventType !== "request") {
    return null;
  }

  const destinationPort = Number(log.metadata?.destinationPort || log.metadata?.port || 0);
  const isWebLogin = [80, 443, 8080].includes(destinationPort) || /login/i.test(log.endpoint || "");
  const failedAttempts = Number(log.metadata?.failedAttempts || 0);
  const requestRate = Number(log.metadata?.requestRate || 0);

  if (!isWebLogin || failedAttempts < 6 || requestRate < 80) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Web Brute Force",
    severity: "High",
    confidence: 0.86,
    source: "rule-engine",
    metadata: {
      category: "authentication",
      family: "web-brute-force",
      destinationPort,
      failedAttempts,
      requestRate,
    },
  });
};

const evaluateIcmpFlood = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  const protocol = getProtocol(log);
  const packets = Number(log?.metadata?.packets || log?.metadata?.network?.packets || 0);
  const requestRate = Number(log?.metadata?.requestRate || log?.metadata?.network?.requestRate || 0);

  if (protocol !== "ICMP" || (packets < 500 && requestRate < 120)) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "ICMP Flood",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      category: "network",
      family: "icmp-flood",
      packets,
      requestRate,
    },
  });
};

const evaluateDataExfiltration = async (log) => {
  if (!isTelemetryLog(log) || log.eventType !== "request") {
    return null;
  }

  const bytes = Number(log.metadata?.bytes || 0);
  const flowCount = Number(log.metadata?.flowCount || 0);

  if (bytes < 90000 || flowCount < 12) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Data Exfiltration",
    severity: "Critical",
    source: "rule-engine",
    metadata: {
      category: "network",
      family: "data-exfiltration",
      bytes,
      flowCount,
    },
  });
};

const evaluateSmbLateralMovement = async (log) => {
  if (!isTelemetryLog(log) || log.eventType !== "request") {
    return null;
  }

  const destinationPort = Number(log.metadata?.destinationPort || log.metadata?.port || 0);
  const smbWrites = Number(log.metadata?.smbWrites || log.metadata?.smb_writes || 0);

  if (destinationPort !== 445 || smbWrites < 20) {
    return null;
  }

  return createDetectionAlert({
    log,
    attackType: "Suspicious SMB Lateral Movement",
    severity: "High",
    confidence: 0.8,
    risk_score: 76,
    source: "rule-engine",
  });
};

const getSnortSeverity = (priority) => {
  const normalized = Number(priority || 0);

  if (normalized <= 1) {
    return "Critical";
  }

  if (normalized === 2) {
    return "High";
  }

  if (normalized === 3) {
    return "Medium";
  }

  return "Low";
};

const evaluateIdsAlert = async (log) => {
  const sensorType = getSensorType(log);
  if (!["snort", "suricata"].includes(sensorType) || !String(log.eventType || "").endsWith(".alert")) {
    return null;
  }

  const attackType =
    log.metadata?.snort?.message ||
    log.metadata?.ids?.signature ||
    log.metadata?.attackType ||
    log.message ||
    "IDS Alert";
  const severity = getSnortSeverity(log.metadata?.snort?.priority);

  return createDetectionAlert({
    log,
    attackType,
    type: attackType,
    severity,
    source: sensorType,
  });
};

const Rule = require("../models/Rule");

const evaluateDynamicRules = async (log) => {
  if (!isTelemetryLog(log)) return [];

  const rules = await Rule.find({ _org_id: log._org_id, enabled: true });
  const results = [];

  for (const rule of rules) {
    let match = rule.logic === "OR" ? false : true;

    for (const condition of rule.conditions) {
      const { field, operator, value } = condition;
      
      // Basic field extraction (handle nested metadata)
      let fieldValue = field.startsWith("metadata.") 
        ? log.metadata?.[field.split(".")[1]] 
        : log[field];
      
      if (fieldValue === undefined) fieldValue = null;

      let conditionMet = false;
      switch (operator) {
        case "equals": conditionMet = String(fieldValue) === String(value); break;
        case "not_equals": conditionMet = String(fieldValue) !== String(value); break;
        case "contains": conditionMet = String(fieldValue || "").toLowerCase().includes(String(value).toLowerCase()); break;
        case "greater_than": conditionMet = Number(fieldValue) > Number(value); break;
        case "less_than": conditionMet = Number(fieldValue) < Number(value); break;
        case "exists": conditionMet = fieldValue !== null; break;
      }

      if (rule.logic === "OR") {
        if (conditionMet) { match = true; break; }
      } else {
        if (!conditionMet) { match = false; break; }
      }
    }

    if (match && rule.conditions.length > 0) {
      results.push(createDetectionAlert({
        log,
        attackType: rule.alertType || rule.name,
        severity: rule.severity,
        source: "dynamic-rules",
        metadata: { ruleId: rule._id, ruleName: rule.name }
      }));
      
      rule.hitCount = (rule.hitCount || 0) + 1;
      rule.lastTriggered = new Date();
      await rule.save();
    }
  }

  return results;
};

const evaluateLog = async (log) => {
  const tasks = [
    evaluateIdsAlert(log),
    evaluateBruteForce(log),
    evaluateUnauthorizedAdminAccess(log),
    evaluateDosBurst(log),
    evaluateIcmpFlood(log),
    evaluateSuspiciousIp(log),
    evaluatePortScan(log),
    evaluateCredentialStuffing(log),
    evaluateDataExfiltration(log),
    evaluateSmbLateralMovement(log),
    evaluateSqlInjection(log),
    evaluateXss(log),
    evaluateDirectoryTraversal(log),
    evaluateRemoteCodeExecution(log),
    evaluateVulnerabilityProbe(log),
    evaluateDnsTunneling(log),
    evaluateMalwareBeaconing(log),
    evaluatePrivilegedServiceExposure(log),
    evaluateSuspiciousProcessCreation(log),
    evaluateSensitiveFileChange(log),
    evaluatePrivilegeEscalation(log),
    evaluatePersistenceChange(log),
    evaluateHostLoginFailures(log),
    evaluateDynamicRules(log),
  ];
  return Promise.all(tasks);
};

module.exports = {
  evaluateLog,
  getSnortSeverity,
  severityProfiles,
  createDetectionAlert,
};
