const axios = require("axios");
const mongoose = require("mongoose");
const Alert = require("../models/Alerts");
const Log = require("../models/Log");
const config = require("../config/env");

const TIME_WINDOW_HOURS = 24;

const buildTimelineBuckets = (logs) => {
  const buckets = new Map();
  const now = Date.now();

  for (let index = TIME_WINDOW_HOURS - 1; index >= 0; index -= 1) {
    const date = new Date(now - index * 60 * 60 * 1000);
    const key = `${String(date.getHours()).padStart(2, "0")}:00`;
    buckets.set(key, {
      time: key,
      events: 0,
      bytes: 0,
      requestRate: 0
    });
  }

  logs.forEach((log) => {
    if (!log.timestamp) {
      return;
    }

    const date = new Date(log.timestamp);
    const key = `${String(date.getHours()).padStart(2, "0")}:00`;
    if (!buckets.has(key)) {
      return;
    }

    const bucket = buckets.get(key);
    const bytes = Number(log.metadata?.bytes || 0);
    const requestRate = Number(log.metadata?.requestRate || 0);

    bucket.events += 1;
    bucket.bytes += bytes;
    bucket.requestRate += requestRate;
  });

  return [...buckets.values()];
};

const groupCounts = (items, accessor, limit = 6) => {
  const counts = items.reduce((accumulator, item) => {
    const key = accessor(item) || "Unknown";
    accumulator[key] = (accumulator[key] || 0) + 1;
    return accumulator;
  }, {});

  return Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, limit);
};

const sumMetric = (logs, accessor) =>
  logs.reduce((total, log) => total + Number(accessor(log) || 0), 0);

const averageMetric = (logs, accessor) => {
  if (!logs.length) {
    return 0;
  }

  return Number((sumMetric(logs, accessor) / logs.length).toFixed(2));
};

const getStats = async (req, res) => {
  try {
    // CRITICAL: Filter all statistics by organization to prevent cross-org data leakage
    const orgFilter = { _org_id: req.orgId };
    const recentLogFilter = {
      ...orgFilter,
      timestamp: { $gte: new Date(Date.now() - TIME_WINDOW_HOURS * 60 * 60 * 1000) }
    };

    const [
      totalAlerts,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      totalLogs,
      latestAlert,
      recentLogs,
      recentAlerts
    ] = await Promise.all([
      Alert.countDocuments(orgFilter),
      Alert.countDocuments({ ...orgFilter, severity: "Critical" }),
      Alert.countDocuments({ ...orgFilter, severity: "High" }),
      Alert.countDocuments({ ...orgFilter, severity: "Medium" }),
      Alert.countDocuments({ ...orgFilter, severity: "Low" }),
      Log.countDocuments(orgFilter),
      Alert.findOne(orgFilter).sort({ timestamp: -1 }),
      Log.find(recentLogFilter).sort({ timestamp: -1 }).limit(500),
      Alert.find(recentLogFilter).sort({ timestamp: -1 }).limit(200)
    ]);

    const protocolDistribution = groupCounts(
      recentLogs,
      (log) => log.metadata?.protocol || log.metadata?.appProtocol || log.metadata?.transport
    );

    const topPorts = groupCounts(
      recentLogs,
      (log) => String(log.metadata?.destinationPort || log.metadata?.port || log.endpoint || "unknown")
    );

    const sourceCountries = groupCounts(
      recentLogs,
      (log) => log.metadata?.sourceCountry
    );

    const destinationCountries = groupCounts(
      recentLogs,
      (log) => log.metadata?.destinationCountry
    );

    const topAttackTypes = groupCounts(
      recentAlerts,
      (alert) => alert.attackType || alert.type
    );

    const topSourceIps = groupCounts(
      recentLogs,
      (log) => log.ip
    );

    const timeline = buildTimelineBuckets(recentLogs);
    const totalBytes = sumMetric(recentLogs, (log) => log.metadata?.bytes);
    const avgDuration = averageMetric(recentLogs, (log) => log.metadata?.duration);
    const avgRequestRate = averageMetric(recentLogs, (log) => log.metadata?.requestRate);
    const totalFailedAttempts = sumMetric(recentLogs, (log) => log.metadata?.failedAttempts);
    const avgFlowCount = averageMetric(recentLogs, (log) => log.metadata?.flowCount);

    const protocolTotals = protocolDistribution.reduce(
      (total, item) => total + item.value,
      0
    );

    return res.json({
      alerts: {
        total: totalAlerts,
        critical: criticalAlerts,
        high: highAlerts,
        medium: mediumAlerts,
        low: lowAlerts
      },
      logs: { total: totalLogs },
      traffic: {
        totalBytes,
        avgDuration,
        avgRequestRate,
        totalFailedAttempts,
        avgFlowCount,
        eventsLast24h: recentLogs.length,
        protocolTotals
      },
      analytics: {
        protocolDistribution,
        topPorts,
        topAttackTypes,
        sourceCountries,
        destinationCountries,
        topSourceIps,
        timeline
      },
      lastDetectionTime: latestAlert?.timestamp || null
    });
  } catch (error) {
    return res.status(500).json({ message: "Failed to fetch stats" });
  }
};

const getHealth = async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? "connected" : "disconnected";
    let idsStatus = "unknown";

    try {
      const response = await axios.get(`${config.idsEngineUrl}/health`, { timeout: 3000 });
      idsStatus = response.data?.status === "ok" ? "online" : "degraded";
    } catch (error) {
      idsStatus = "offline";
    }

    // CRITICAL: Last alert query must be filtered by organization
    const lastAlert = await Alert.findOne({ _org_id: req.orgId }).sort({ timestamp: -1 });

    return res.json({
      status: "ok",
      database: dbStatus,
      idsEngine: idsStatus,
      lastDetectionTime: lastAlert?.timestamp || null
    });
  } catch (error) {
    return res.status(500).json({ message: "Failed to fetch health" });
  }
};

module.exports = { getStats, getHealth };
