const {
  initSocket,
  getIo,
  emitToOrganization,
  emitToRole,
  emitGlobal,
  isSocketReady,
  orgRoom,
  roleRoom,
} = require("../socket");

const normalizeOrgId = (orgId) => orgId?.toString?.() || orgId || null;

const compactMeta = (meta = {}) => ({
  source: meta.source || "unknown",
  mode: meta.mode || "live",
  insertedCount: Number(meta.insertedCount || 0),
  duplicateCount: Number(meta.duplicateCount || 0),
  severity: meta.severity || null,
  type: meta.type || null,
  queueDepth: meta.queueDepth ?? null,
});

const basePayload = (orgId, payload = {}) => ({
  organizationId: normalizeOrgId(orgId),
  timestamp: new Date().toISOString(),
  ...payload,
});

const emitDashboardUpdate = (orgId, payload = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId) return false;

  return emitToOrganization(
    normalizedOrgId,
    "dashboard:update",
    basePayload(normalizedOrgId, payload)
  );
};

const emitReportsUpdate = (orgId, payload = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId) return false;

  return emitToOrganization(
    normalizedOrgId,
    "reports:update",
    basePayload(normalizedOrgId, payload)
  );
};

const emitLiveUpdate = (orgId, payload = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId) return false;

  return emitToOrganization(
    normalizedOrgId,
    "live:update",
    basePayload(normalizedOrgId, payload)
  );
};

const emitNewLog = (orgId, log, meta = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId || !log) return false;

  const items =
    Array.isArray(meta.items) && meta.items.length > 0 ? meta.items : [log];

  const payload = basePayload(normalizedOrgId, {
    type: meta.type || "created",
    data: log,
    items,
    meta: compactMeta({
      ...meta,
      insertedCount: meta.insertedCount || items.length || 1,
      source: meta.source || log.source || "unknown",
    }),
  });

  emitToOrganization(normalizedOrgId, "logs:new", payload);
  emitToOrganization(normalizedOrgId, "log:new", payload);

  emitLiveUpdate(normalizedOrgId, {
    type: "log-created",
    source: meta.source || log.source || "unknown",
    latestLog: log,
    items,
    insertedCount: meta.insertedCount || items.length || 1,
    duplicateCount: meta.duplicateCount || 0,
  });

  emitDashboardUpdate(normalizedOrgId, {
    type: "log-created",
    source: meta.source || log.source || "unknown",
    lastLog: log,
    insertedCount: meta.insertedCount || items.length || 1,
    duplicateCount: meta.duplicateCount || 0,
  });

  emitReportsUpdate(normalizedOrgId, {
    source: meta.source || log.source || "unknown",
    type: "log-created",
    latestLog: log,
    insertedCount: meta.insertedCount || items.length || 1,
    duplicateCount: meta.duplicateCount || 0,
  });

  return true;
};

const emitNewAlert = (orgId, alert, meta = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId || !alert) return false;

  const payload = basePayload(normalizedOrgId, {
    type: meta.type || "created",
    data: alert,
    meta: compactMeta({
      ...meta,
      source: meta.source || alert.source || "unknown",
      severity: meta.severity || alert.severity || "Unknown",
    }),
  });

  emitToOrganization(normalizedOrgId, "alerts:new", payload);
  emitToOrganization(normalizedOrgId, "alert:new", payload);

  emitLiveUpdate(normalizedOrgId, {
    type: meta.type || "alert-created",
    source: meta.source || alert.source || "unknown",
    latestAlert: alert,
    severity: meta.severity || alert.severity || "Unknown",
  });

  emitDashboardUpdate(normalizedOrgId, {
    type: meta.type || "alert-created",
    source: meta.source || alert.source || "unknown",
    lastAlert: alert,
    severity: meta.severity || alert.severity || "Unknown",
  });

  emitReportsUpdate(normalizedOrgId, {
    source: meta.source || alert.source || "unknown",
    type: meta.type || "alert-created",
    latestAlert: alert,
    severity: meta.severity || alert.severity || "Unknown",
  });

  return true;
};

const emitCollectorHeartbeat = (orgId, heartbeat, meta = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId || !heartbeat) return false;

  const status = heartbeat.status || heartbeat.agent_status || "online";
  const queueDepth = heartbeat.queueDepth ?? heartbeat.queue_depth ?? 0;

  const payload = basePayload(normalizedOrgId, {
    data: heartbeat,
    meta: compactMeta({
      ...meta,
      source: "collector",
      type: "collector-heartbeat",
      queueDepth,
    }),
    status,
    assetId: heartbeat.assetId || heartbeat.asset_id || null,
    assetName: heartbeat.assetName || heartbeat.asset_name || null,
    agentType: heartbeat.agentType || heartbeat.agent_type || null,
    queueDepth,
    telemetryTypes: heartbeat.telemetryTypes || heartbeat.telemetry_types || [],
  });

  emitToOrganization(normalizedOrgId, "collector:heartbeat", payload);
  emitToOrganization(normalizedOrgId, "agents:heartbeat", payload);

  emitToOrganization(
    normalizedOrgId,
    "health:update",
    basePayload(normalizedOrgId, {
      status,
      assetId: payload.assetId,
      assetName: payload.assetName,
      agentType: payload.agentType,
      queueDepth,
      telemetryTypes: payload.telemetryTypes,
      meta,
    })
  );

  emitDashboardUpdate(normalizedOrgId, {
    type: "collector-heartbeat",
    source: "collector",
    status,
    assetId: payload.assetId,
    agentType: payload.agentType,
    queueDepth,
  });

  emitReportsUpdate(normalizedOrgId, {
    source: "collector",
    type: "collector-heartbeat",
    status,
    queueDepth,
    agentType: payload.agentType,
  });

  return true;
};

const emitStreamEvent = (orgId, payload = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId) return false;

  const eventPayload = basePayload(normalizedOrgId, payload);

  emitToOrganization(normalizedOrgId, "stream:event", eventPayload);

  if (
    payload.type === "telemetry.batch.persisted" ||
    payload.type === "alert.created" ||
    payload.type === "incident.updated"
  ) {
    emitLiveUpdate(normalizedOrgId, eventPayload);
  }

  return true;
};

const emitIncidentUpdate = (orgId, incident, meta = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId || !incident) return false;

  const payload = basePayload(normalizedOrgId, {
    type: meta.type || "incident-updated",
    data: incident,
    meta,
  });

  emitToOrganization(normalizedOrgId, "incidents:update", payload);
  emitLiveUpdate(normalizedOrgId, payload);
  emitDashboardUpdate(normalizedOrgId, {
    type: meta.type || "incident-updated",
    lastIncident: incident,
  });

  return true;
};

const emitSystemHealth = (orgId, health = {}, meta = {}) => {
  const normalizedOrgId = normalizeOrgId(orgId);
  if (!normalizedOrgId) return false;

  return emitToOrganization(
    normalizedOrgId,
    "health:update",
    basePayload(normalizedOrgId, {
      ...health,
      meta,
    })
  );
};

module.exports = {
  initSocket,
  getIo,
  isSocketReady,

  emitToOrganization,
  emitToRole,
  emitGlobal,

  orgRoom,
  roleRoom,

  emitNewLog,
  emitNewAlert,
  emitDashboardUpdate,
  emitReportsUpdate,
  emitLiveUpdate,
  emitCollectorHeartbeat,
  emitStreamEvent,
  emitIncidentUpdate,
  emitSystemHealth,
};