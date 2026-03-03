const axios = require("axios");
const mongoose = require("mongoose");
const Alert = require("../models/Alerts");
const Log = require("../models/Log");
const config = require("../config/env");

const getStats = async (req, res) => {
  try {
    // CRITICAL: Filter all statistics by organization to prevent cross-org data leakage
    const orgFilter = { _org_id: req.orgId };

    const [
      totalAlerts,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      totalLogs,
      latestAlert
    ] = await Promise.all([
      Alert.countDocuments(orgFilter),
      Alert.countDocuments({ ...orgFilter, severity: "Critical" }),
      Alert.countDocuments({ ...orgFilter, severity: "High" }),
      Alert.countDocuments({ ...orgFilter, severity: "Medium" }),
      Alert.countDocuments({ ...orgFilter, severity: "Low" }),
      Log.countDocuments(orgFilter),
      Alert.findOne(orgFilter).sort({ timestamp: -1 })
    ]);

    return res.json({
      alerts: {
        total: totalAlerts,
        critical: criticalAlerts,
        high: highAlerts,
        medium: mediumAlerts,
        low: lowAlerts
      },
      logs: { total: totalLogs },
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
