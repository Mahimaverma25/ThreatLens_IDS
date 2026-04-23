const { getIdsEngineHealth } = require("../services/detection.service");
const ThreatIndicator = require("../models/ThreatIndicator");
const { buildThreatIntelSummary, buildThreatMapSummary } = require("../services/threat-intel.service");

const getThreatIntel = async (req, res) => {
  const data = await buildThreatIntelSummary(req.orgId);
  return res.json({ data });
};

const getThreatMap = async (req, res) => {
  const data = await buildThreatMapSummary(req.orgId);
  return res.json({ data });
};

const getModelHealthDetails = async (req, res) => {
  const idsHealth = await getIdsEngineHealth();
  return res.json({
    data: {
      idsEngine: idsHealth,
    },
  });
};

const createThreatIndicator = async (req, res) => {
  const { indicator_type, value, confidence, notes } = req.body || {};

  if (!String(value || "").trim()) {
    return res.status(400).json({ message: "value is required" });
  }

  const indicator = await ThreatIndicator.create({
    _org_id: req.orgId,
    indicator_type: indicator_type || "ip",
    value: String(value).trim(),
    confidence: confidence || "medium",
    notes: notes || "",
    created_by: req.user?.sub || null,
  });

  return res.status(201).json({ data: indicator });
};

const listThreatIndicators = async (req, res) => {
  const indicators = await ThreatIndicator.find({ _org_id: req.orgId }).sort({ createdAt: -1 });
  return res.json({ data: indicators, total: indicators.length });
};

const deleteThreatIndicator = async (req, res) => {
  const indicator = await ThreatIndicator.findOneAndDelete({
    _id: req.params.id,
    _org_id: req.orgId,
  });

  if (!indicator) {
    return res.status(404).json({ message: "Indicator not found" });
  }

  return res.json({ message: "Indicator deleted successfully" });
};

module.exports = {
  getThreatIntel,
  getThreatMap,
  getModelHealthDetails,
  createThreatIndicator,
  listThreatIndicators,
  deleteThreatIndicator,
};
