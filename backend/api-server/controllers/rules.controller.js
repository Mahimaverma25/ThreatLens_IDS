const Rule = require("../models/Rule");

const slugify = (value = "") =>
  String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || `rule-${Date.now()}`;

const sanitizeConditions = (conditions) => {
  if (!Array.isArray(conditions)) {
    return [];
  }

  return conditions
    .map((condition) => ({
      field: String(condition?.field || "").trim(),
      operator: String(condition?.operator || "").trim(),
      value: condition?.value ?? "",
    }))
    .filter((condition) => condition.field && condition.operator);
};

const serializeRule = (rule) => {
  const raw = rule?.toObject ? rule.toObject() : rule;
  const conditions = sanitizeConditions(raw?.conditions);

  return {
    ...raw,
    ruleId: raw?.ruleId || slugify(raw?.name),
    logic: raw?.logic || "AND",
    action: raw?.action || "alert",
    alertType: raw?.alertType || raw?.name || "Custom Rule Match",
    cooldownMinutes: Number(raw?.cooldownMinutes || 10),
    hitCount: Number(raw?.hitCount || 0),
    conditions,
  };
};

const DEFAULT_RULES = [
  {
    name: "Brute Force Login Attempts",
    description: "Detect repeated failed authentication attempts from the same source.",
    category: "auth",
    severity: "High",
    enabled: true,
    logic: "AND",
    action: "alert",
    alertType: "Brute Force Login Attempts",
    cooldownMinutes: 10,
    conditions: [
      { field: "eventType", operator: "contains", value: "auth." },
      { field: "metadata.outcome", operator: "equals", value: "failure" },
      { field: "metadata.failedAttempts", operator: "greater_than", value: 4 },
    ],
  },
  {
    name: "Request Burst / DoS",
    description: "Detect sustained request bursts that resemble denial-of-service pressure.",
    category: "network",
    severity: "Critical",
    enabled: true,
    logic: "AND",
    action: "alert",
    alertType: "Request Burst / DoS",
    cooldownMinutes: 5,
    conditions: [
      { field: "source", operator: "in", value: ["snort", "suricata", "host", "agent"] },
      { field: "metadata.requestRate", operator: "greater_than", value: 150 },
    ],
  },
  {
    name: "ML Anomalous Activity",
    description: "Promote high-confidence ML anomalies into analyst-visible detections.",
    category: "custom",
    severity: "High",
    enabled: true,
    logic: "AND",
    action: "alert",
    alertType: "ML Anomalous Activity",
    cooldownMinutes: 10,
    conditions: [
      { field: "source", operator: "equals", value: "ids-engine-ml" },
      { field: "metadata.idsEngine.is_anomaly", operator: "exists", value: true },
    ],
  },
];

const ensureDefaultRules = async (orgId, userId = null) => {
  const total = await Rule.countDocuments({ _org_id: orgId });
  if (total > 0) {
    return;
  }

  await Rule.insertMany(
    DEFAULT_RULES.map((rule) => ({
      _org_id: orgId,
      created_by: userId,
      ...rule,
      conditions: sanitizeConditions(rule.conditions),
    }))
  );
};

const listRules = async (req, res) => {
  await ensureDefaultRules(req.orgId, req.user?.sub || null);

  const filters = { _org_id: req.orgId };
  if (req.query.category) {
    filters.category = req.query.category;
  }
  if (req.query.enabled === "true") {
    filters.enabled = true;
  }
  if (req.query.enabled === "false") {
    filters.enabled = false;
  }

  const rules = await Rule.find(filters).sort({ enabled: -1, created_at: -1 });
  const data = rules.map(serializeRule);
  return res.json({ data, total: data.length });
};

const createRule = async (req, res) => {
  const payload = req.body || {};
  if (!payload.name) {
    return res.status(400).json({ message: "name is required" });
  }

  const conditions = sanitizeConditions(payload.conditions);
  if (conditions.length === 0) {
    return res.status(400).json({ message: "At least one valid condition is required" });
  }

  const rule = await Rule.create({
    _org_id: req.orgId,
    created_by: req.user.sub,
    name: payload.name,
    description: payload.description || "",
    category: payload.category || "custom",
    severity: payload.severity || "Medium",
    enabled: payload.enabled !== false,
    logic: payload.logic || "AND",
    action: payload.action || "alert",
    alertType: payload.alertType || payload.name,
    cooldownMinutes: Number(payload.cooldownMinutes || 10),
    conditions,
  });

  return res.status(201).json({ data: serializeRule(rule) });
};

const updateRule = async (req, res) => {
  const rule = await Rule.findOne({
    _id: req.params.id,
    _org_id: req.orgId,
  });

  if (!rule) {
    return res.status(404).json({ message: "Rule not found" });
  }

  const allowedFields = [
    "name",
    "description",
    "category",
    "severity",
    "enabled",
    "logic",
    "action",
    "alertType",
    "cooldownMinutes",
  ];

  allowedFields.forEach((field) => {
    if (req.body?.[field] !== undefined) {
      rule[field] = req.body[field];
    }
  });

  if (req.body?.conditions !== undefined) {
    const conditions = sanitizeConditions(req.body.conditions);
    if (conditions.length === 0) {
      return res.status(400).json({ message: "At least one valid condition is required" });
    }
    rule.conditions = conditions;
  }

  await rule.save();

  return res.json({ data: serializeRule(rule) });
};

const deleteRule = async (req, res) => {
  const rule = await Rule.findOneAndDelete({
    _id: req.params.id,
    _org_id: req.orgId,
  });

  if (!rule) {
    return res.status(404).json({ message: "Rule not found" });
  }

  return res.json({ message: "Rule deleted successfully" });
};

module.exports = {
  listRules,
  createRule,
  updateRule,
  deleteRule,
};
