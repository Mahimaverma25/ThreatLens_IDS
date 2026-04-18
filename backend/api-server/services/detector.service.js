const Alert = require("../models/Alerts");
const Log = require("../models/Log");
const config = require("../config/env");
const { createAlert, updateAlert } = require("./alert.service");

const windowStart = () =>
  new Date(Date.now() - config.alertCorrelationWindowMins * 60 * 1000);

const severityToConfidence = {
  Critical: 0.95,
  High: 0.82,
  Medium: 0.64,
  Low: 0.42
};

const severityToRiskScore = {
  Critical: 92,
  High: 76,
  Medium: 58,
  Low: 34
};

const TELEMETRY_SOURCES = new Set(["agent", "simulator", "upload", "ids-engine", "snort"]);

const isTelemetryLog = (log) => TELEMETRY_SOURCES.has(log.source);

const appendRelatedLog = async (alert, logId) => {
  if (!alert.relatedLogs.some((id) => id.toString() === logId.toString())) {
    alert.relatedLogs.push(logId);
    await alert.save();
    await updateAlert(alert);
  }
};

const upsertAlert = async ({
  orgId,
  attackType,
  ip,
  severity,
  type,
  relatedLogs,
  confidence,
  risk_score,
  source = "ids-engine"
}) => {
  const existing = await Alert.findOne({
    _org_id: orgId,
    attackType,
    ip,
    timestamp: { $gte: windowStart() },
    status: { $ne: "Resolved" }
  });

  if (existing) {
    for (const logId of relatedLogs) {
      await appendRelatedLog(existing, logId);
    }
    return existing;
  }

  return createAlert({
    _org_id: orgId,
    type,
    attackType,
    ip,
    severity,
    confidence,
    risk_score,
    relatedLogs,
    source
  });
};

const evaluateBruteForce = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  if (log.eventType !== "auth.login" || log.metadata?.success !== false) {
    return null;
  }

  const failures = await Log.countDocuments({
    eventType: "auth.login",
    ip: log.ip,
    "metadata.success": false,
    timestamp: { $gte: windowStart() }
  });

  if (failures >= config.bruteforceThreshold) {
    return upsertAlert({
      orgId: log._org_id,
      attackType: "Brute Force Login Attempts",
      type: "Brute Force Login Attempts",
      ip: log.ip || "unknown",
      severity: "High",
      confidence: severityToConfidence.High,
      risk_score: severityToRiskScore.High,
      relatedLogs: [log._id]
    });
  }

  return null;
};

const evaluateUnauthorizedAdminAccess = async (log) => {
  if (log.eventType !== "authz.denied") {
    return null;
  }

  const requiresAdmin = (log.metadata?.requiredRoles || []).includes("admin");
  if (!requiresAdmin) {
    return null;
  }

  return upsertAlert({
    orgId: log._org_id,
    attackType: "Unauthorized Admin Access",
    type: "Unauthorized Admin Access",
    ip: log.ip || "unknown",
    severity: "Critical",
    confidence: severityToConfidence.Critical,
    risk_score: severityToRiskScore.Critical,
    relatedLogs: [log._id]
  });
};

const evaluateDosBurst = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  if (log.eventType !== "request") {
    return null;
  }

  const count = await Log.countDocuments({
    _org_id: log._org_id,
    eventType: "request",
    ip: log.ip,
    timestamp: { $gte: new Date(Date.now() - 60 * 1000) }
  });

  if (count >= config.dosThresholdPerMinute) {
    return upsertAlert({
      orgId: log._org_id,
      attackType: "Request Burst / DoS",
      type: "Request Burst / DoS",
      ip: log.ip || "unknown",
      severity: "Critical",
      confidence: severityToConfidence.Critical,
      risk_score: severityToRiskScore.Critical,
      relatedLogs: [log._id]
    });
  }

  return null;
};

const evaluateSuspiciousIp = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  if (!log.ip) {
    return null;
  }

  const distinctEndpoints = await Log.distinct("endpoint", {
    _org_id: log._org_id,
    ip: log.ip,
    timestamp: { $gte: windowStart() }
  });

  if (distinctEndpoints.length >= 10) {
    return upsertAlert({
      orgId: log._org_id,
      attackType: "Suspicious IP Activity",
      type: "Suspicious IP Activity",
      ip: log.ip || "unknown",
      severity: "Medium",
      confidence: severityToConfidence.Medium,
      risk_score: severityToRiskScore.Medium,
      relatedLogs: [log._id]
    });
  }

  return null;
};

const evaluatePortScan = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  if (!log.ip) {
    return null;
  }

  const destinations = await Log.distinct("metadata.destinationPort", {
    _org_id: log._org_id,
    ip: log.ip,
    eventType: "request",
    timestamp: { $gte: windowStart() }
  });

  const validDestinations = destinations.filter((value) => value !== null && value !== undefined);

  if (validDestinations.length >= 10) {
    return upsertAlert({
      orgId: log._org_id,
      attackType: "Port Scan Activity",
      type: "Port Scan Activity",
      ip: log.ip || "unknown",
      severity: "High",
      confidence: severityToConfidence.High,
      risk_score: severityToRiskScore.High,
      relatedLogs: [log._id]
    });
  }

  return null;
};

const evaluateCredentialStuffing = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  if (log.eventType !== "request") {
    return null;
  }

  const destinationPort = Number(log.metadata?.destinationPort || log.metadata?.port || 0);
  const isWebLogin = [80, 443, 8080].includes(destinationPort) || /login/i.test(log.endpoint || "");
  const failedAttempts = Number(log.metadata?.failedAttempts || 0);
  const requestRate = Number(log.metadata?.requestRate || 0);

  if (!isWebLogin || failedAttempts < 6 || requestRate < 80) {
    return null;
  }

  return upsertAlert({
    orgId: log._org_id,
    attackType: "Credential Stuffing Attempt",
    type: "Credential Stuffing Attempt",
    ip: log.ip || "unknown",
    severity: "High",
    confidence: 0.86,
    risk_score: 79,
    relatedLogs: [log._id]
  });
};

const evaluateDataExfiltration = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  if (log.eventType !== "request") {
    return null;
  }

  const bytes = Number(log.metadata?.bytes || 0);
  const flowCount = Number(log.metadata?.flowCount || 0);

  if (bytes < 90000 || flowCount < 12) {
    return null;
  }

  return upsertAlert({
    orgId: log._org_id,
    attackType: "Potential Data Exfiltration",
    type: "Potential Data Exfiltration",
    ip: log.ip || "unknown",
    severity: "Critical",
    confidence: severityToConfidence.Critical,
    risk_score: 88,
    relatedLogs: [log._id]
  });
};

const evaluateSmbLateralMovement = async (log) => {
  if (!isTelemetryLog(log)) {
    return null;
  }

  if (log.eventType !== "request") {
    return null;
  }

  const destinationPort = Number(log.metadata?.destinationPort || log.metadata?.port || 0);
  const smbWrites = Number(log.metadata?.smbWrites || log.metadata?.smb_writes || 0);

  if (destinationPort !== 445 || smbWrites < 20) {
    return null;
  }

  return upsertAlert({
    orgId: log._org_id,
    attackType: "Suspicious SMB Lateral Movement",
    type: "Suspicious SMB Lateral Movement",
    ip: log.ip || "unknown",
    severity: "High",
    confidence: 0.8,
    risk_score: 76,
    relatedLogs: [log._id]
  });
};

const getSnortSeverity = (priority) => {
  const value = Number(priority || 0);

  if (value <= 1) {
    return "Critical";
  }

  if (value === 2) {
    return "High";
  }

  if (value === 3) {
    return "Medium";
  }

  return "Low";
};

const evaluateSnortAlert = async (log) => {
  if (log.source !== "snort" || log.eventType !== "snort.alert") {
    return null;
  }

  const attackType =
    log.metadata?.snort?.message ||
    log.metadata?.attackType ||
    log.message ||
    "Snort Alert";
  const severity = getSnortSeverity(log.metadata?.snort?.priority);

  return upsertAlert({
    orgId: log._org_id,
    attackType,
    type: attackType,
    ip: log.ip || log.metadata?.snort?.srcIp || "unknown",
    severity,
    confidence: severityToConfidence[severity],
    risk_score: severityToRiskScore[severity],
    relatedLogs: [log._id],
    source: "snort"
  });
};

const evaluateLog = async (log) => {
  await Promise.all([
    evaluateSnortAlert(log),
    evaluateBruteForce(log),
    evaluateUnauthorizedAdminAccess(log),
    evaluateDosBurst(log),
    evaluateSuspiciousIp(log),
    evaluatePortScan(log),
    evaluateCredentialStuffing(log),
    evaluateDataExfiltration(log),
    evaluateSmbLateralMovement(log)
  ]);
};

module.exports = { evaluateLog }
