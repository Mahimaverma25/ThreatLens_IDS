const {
  initSocket,
  getIo,
  emitToOrganization,
  emitToRole,
  emitGlobal,
  orgRoom,
  roleRoom,
} = require("../socket");

const normalizeOrgId = (orgId) => orgId?.toString?.() || orgId || null;

const emitDashboardUpdate = (orgId, payload = {}) => {
  emitToOrganization(normalizeOrgId(orgId), "dashboard:update", {
    organizationId: normalizeOrgId(orgId),
    timestamp: new Date().toISOString(),
    ...payload,
  });
};

const emitNewLog = (orgId, log, meta = {}) => {
  if (!log) return;

  const payload = {
    type: "created",
    organizationId: normalizeOrgId(orgId),
    data: log,
    items: Array.isArray(meta.items) && meta.items.length > 0 ? meta.items : [log],
    meta,
    timestamp: new Date().toISOString(),
  };

  emitToOrganization(normalizeOrgId(orgId), "logs:new", payload);
  emitToOrganization(normalizeOrgId(orgId), "log:new", payload);
};

const emitNewAlert = (orgId, alert, meta = {}) => {
  if (!alert) return;

  const payload = {
    type: meta.type || "created",
    organizationId: normalizeOrgId(orgId),
    data: alert,
    meta,
    timestamp: new Date().toISOString(),
  };

  emitToOrganization(normalizeOrgId(orgId), "alerts:new", payload);
  emitToOrganization(normalizeOrgId(orgId), "alert:new", payload);
};

const emitCollectorHeartbeat = (orgId, heartbeat, meta = {}) => {
  if (!heartbeat) return;

  const payload = {
    organizationId: normalizeOrgId(orgId),
    data: heartbeat,
    meta,
    timestamp: heartbeat.receivedAt || new Date().toISOString(),
  };

  emitToOrganization(normalizeOrgId(orgId), "collector:heartbeat", payload);
  emitToOrganization(normalizeOrgId(orgId), "agents:heartbeat", payload);
  emitToOrganization(normalizeOrgId(orgId), "health:update", {
    organizationId: normalizeOrgId(orgId),
    status: heartbeat.status || "unknown",
    assetId: heartbeat.assetId || heartbeat.asset_id || null,
    assetName: heartbeat.assetName || heartbeat.asset_name || null,
    agentType: heartbeat.agentType || heartbeat.agent_type || null,
    queueDepth: heartbeat.queueDepth ?? heartbeat.queue_depth ?? 0,
    telemetryTypes: heartbeat.telemetryTypes || heartbeat.telemetry_types || [],
    timestamp: heartbeat.receivedAt || new Date().toISOString(),
    meta,
  });
};

const emitStreamEvent = (orgId, payload = {}) => {
  emitToOrganization(normalizeOrgId(orgId), "stream:event", {
    organizationId: normalizeOrgId(orgId),
    timestamp: new Date().toISOString(),
    ...payload,
  });
};

module.exports = {
  initSocket,
  getIo,
  emitToOrganization,
  emitToRole,
  emitGlobal,
  orgRoom,
  roleRoom,
  emitNewLog,
  emitNewAlert,
  emitDashboardUpdate,
  emitCollectorHeartbeat,
  emitStreamEvent,
};
