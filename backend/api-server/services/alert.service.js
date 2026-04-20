const { v4: uuidv4 } = require("uuid");

const Alert = require("../models/Alerts");
const config = require("../config/env");
const { emitToOrganization } = require("../socket");

const correlationWindowStart = () =>
  new Date(Date.now() - config.alertCorrelationWindowMins * 60 * 1000);

const buildSocketEnvelope = (alert, type, meta = {}) => ({
  type,
  organizationId: alert._org_id?.toString?.() || alert._org_id || null,
  data: alert,
  meta,
});

const emitAlert = (eventName, alert, type, meta = {}) => {
  emitToOrganization(alert._org_id, eventName, buildSocketEnvelope(alert, type, meta));
};

const createAlert = async (payload) => {
  const alert = await Alert.create({
    alertId: uuidv4(),
    ...payload,
  });

  emitAlert("alerts:new", alert, "created");
  return alert;
};

const updateAlert = async (alert, meta = {}) => {
  emitAlert("alerts:update", alert, "updated", meta);
  return alert;
};

const appendRelatedLogs = async (alert, relatedLogs = []) => {
  let changed = false;

  relatedLogs.forEach((logId) => {
    if (!logId) {
      return;
    }

    const exists = alert.relatedLogs.some((existingId) => existingId.toString() === logId.toString());
    if (!exists) {
      alert.relatedLogs.push(logId);
      changed = true;
    }
  });

  if (changed) {
    await alert.save();
    await updateAlert(alert, { relatedLogsAdded: relatedLogs.length });
  }

  return alert;
};

const hasMeaningfulValue = (value) => {
  if (value === null || value === undefined) return false;
  const normalized = String(value).trim().toLowerCase();
  return Boolean(normalized) && normalized !== "unknown" && normalized !== "n/a" && normalized !== "-";
};

const mergeMetadata = (current = {}, incoming = {}) => {
  const next = { ...current };

  Object.entries(incoming).forEach(([key, value]) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      next[key] = mergeMetadata(current?.[key] || {}, value);
      return;
    }

    if (!hasMeaningfulValue(next[key]) && hasMeaningfulValue(value)) {
      next[key] = value;
    }
  });

  return next;
};

const upsertCorrelatedAlert = async ({
  orgId,
  assetId,
  attackType,
  ip,
  severity,
  type,
  relatedLogs = [],
  confidence,
  risk_score,
  source = "ids-engine",
  match = {},
  metadata = {},
}) => {
  const existing = await Alert.findOne({
    _org_id: orgId,
    attackType,
    ip,
    source,
    status: { $ne: "Resolved" },
    timestamp: { $gte: correlationWindowStart() },
    ...match,
  });

  if (existing) {
    existing.metadata = mergeMetadata(existing.metadata || {}, metadata || {});
    existing.markModified("metadata");
    await existing.save();
    return appendRelatedLogs(existing, relatedLogs);
  }

  return createAlert({
    _org_id: orgId,
    _asset_id: assetId,
    type,
    attackType,
    ip,
    severity,
    confidence,
    risk_score,
    relatedLogs,
    source,
    metadata,
  });
};

module.exports = {
  createAlert,
  updateAlert,
  upsertCorrelatedAlert,
};
