const Alert = require("../models/Alerts");
const Log = require("../models/Log");
const config = require("../config/env");
const { createAlert, updateAlert } = require("./alert.service");

const windowStart = () =>
  new Date(Date.now() - config.alertCorrelationWindowMins * 60 * 1000);

const appendRelatedLog = async (alert, logId) => {
  if (!alert.relatedLogs.some((id) => id.toString() === logId.toString())) {
    alert.relatedLogs.push(logId);
    await alert.save();
    await updateAlert(alert);
  }
};

const upsertAlert = async ({ attackType, ip, severity, type, relatedLogs }) => {
  const existing = await Alert.findOne({
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
    type,
    attackType,
    ip,
    severity,
    relatedLogs,
    source: "ids-engine"
  });
};

const evaluateBruteForce = async (log) => {
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
      attackType: "Brute Force Login Attempts",
      type: "Brute Force Login Attempts",
      ip: log.ip || "unknown",
      severity: "High",
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
    attackType: "Unauthorized Admin Access",
    type: "Unauthorized Admin Access",
    ip: log.ip || "unknown",
    severity: "Critical",
    relatedLogs: [log._id]
  });
};

const evaluateDosBurst = async (log) => {
  if (log.eventType !== "request") {
    return null;
  }

  const count = await Log.countDocuments({
    eventType: "request",
    ip: log.ip,
    timestamp: { $gte: new Date(Date.now() - 60 * 1000) }
  });

  if (count >= config.dosThresholdPerMinute) {
    return upsertAlert({
      attackType: "Request Burst / DoS",
      type: "Request Burst / DoS",
      ip: log.ip || "unknown",
      severity: "Critical",
      relatedLogs: [log._id]
    });
  }

  return null;
};

const evaluateSuspiciousIp = async (log) => {
  if (!log.ip) {
    return null;
  }

  const distinctEndpoints = await Log.distinct("endpoint", {
    ip: log.ip,
    timestamp: { $gte: windowStart() }
  });

  if (distinctEndpoints.length >= 10) {
    return upsertAlert({
      attackType: "Suspicious IP Activity",
      type: "Suspicious IP Activity",
      ip: log.ip || "unknown",
      severity: "Medium",
      relatedLogs: [log._id]
    });
  }

  return null;
};

const evaluateLog = async (log) => {
  await Promise.all([
    evaluateBruteForce(log),
    evaluateUnauthorizedAdminAccess(log),
    evaluateDosBurst(log),
    evaluateSuspiciousIp(log)
  ]);
};

module.exports = { evaluateLog }
