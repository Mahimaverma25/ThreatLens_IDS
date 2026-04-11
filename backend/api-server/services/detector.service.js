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

const upsertAlert = async ({
  orgId,
  attackType,
  ip,
  severity,
  type,
  relatedLogs
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
      orgId: log._org_id,
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
    orgId: log._org_id,
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
