const crypto = require("crypto");

const APIKey = require("../models/APIKey");
const AgentHeartbeat = require("../models/AgentHeartbeat");
const Asset = require("../models/Asset");
const {
  emitCollectorHeartbeat,
  emitDashboardUpdate,
} = require("../services/socket.service");

const createAgentAsset = async (req, res) => {
  const {
    asset_name,
    hostname,
    ip_address,
    host_platform,
    asset_environment,
    telemetry_types = ["host"],
    asset_criticality = "medium",
  } = req.body || {};

  if (!asset_name) {
    return res.status(400).json({ message: "asset_name is required" });
  }

  const asset = await Asset.create({
    _org_id: req.orgId,
    asset_id: `agent-${crypto.randomBytes(4).toString("hex")}`,
    asset_name,
    asset_type: "agent",
    asset_environment: asset_environment || "production",
    asset_criticality,
    hostname: hostname || asset_name,
    ip_address: ip_address || "",
    status: "active",
    agent_status: "offline",
    host_platform: host_platform || "",
    telemetry_types: Array.isArray(telemetry_types) ? telemetry_types : ["host"],
  });

  const { token, secret } = APIKey.generate(req.orgId);
  const apiKey = await APIKey.create({
    token,
    secret_key_hash: crypto.createHash("sha256").update(secret).digest("hex"),
    _org_id: req.orgId,
    _asset_id: asset._id,
    key_name: `${asset.asset_name}-agent-key`,
    created_by: req.user.sub,
    is_active: true,
  });

  return res.status(201).json({
    data: {
      asset,
      credentials: {
        token,
        secret,
        key_name: apiKey.key_name,
      },
    },
  });
};

const recordHeartbeat = async (req, res) => {
  if (!req.orgId || !req.assetId || !req.asset) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const payload = req.body || {};
  const heartbeat = await AgentHeartbeat.create({
    _org_id: req.orgId,
    _asset_id: req.assetId,
    agent_type: payload.agent_type || "unknown",
    asset_id: req.asset?.asset_id || payload.asset_id || "",
    hostname: payload.hostname || req.asset?.hostname || "",
    host_platform: payload.host_platform || req.asset?.host_platform || "",
    agent_version: payload.agent_version || req.headers["x-agent-version"] || "",
    telemetry_types: Array.isArray(payload.telemetry_types) ? payload.telemetry_types : [],
    queue_depth: Number(payload.queue_depth || 0),
    status: payload.status || "online",
    ip: req.ip,
    metadata: payload.metadata || {},
  });

  await Asset.updateOne(
    { _id: req.assetId },
    {
      $set: {
        agent_status: payload.status === "error" ? "error" : "online",
        agent_last_seen: heartbeat.receivedAt,
        agent_version: heartbeat.agent_version || req.asset?.agent_version || "unknown",
        host_platform: heartbeat.host_platform || req.asset?.host_platform || "",
        telemetry_types: heartbeat.telemetry_types,
      },
    }
  );

  const heartbeatPayload = {
    assetId: req.assetId?.toString?.() || req.assetId,
    assetName: req.asset?.asset_name || null,
    hostname: heartbeat.hostname,
    hostPlatform: heartbeat.host_platform,
    status: heartbeat.status,
    agentType: heartbeat.agent_type,
    telemetryTypes: heartbeat.telemetry_types,
    queueDepth: heartbeat.queue_depth,
    receivedAt: heartbeat.receivedAt,
    metadata: heartbeat.metadata || {},
  };

  emitCollectorHeartbeat(req.orgId, heartbeatPayload, {
    source: "collector-heartbeat",
    assetId: heartbeatPayload.assetId,
  });

  emitDashboardUpdate(req.orgId, {
    source: "collector-heartbeat",
    mode: "heartbeat",
    collector: heartbeatPayload,
  });

  return res.status(201).json({
    success: true,
    receivedAt: heartbeat.receivedAt,
  });
};

const listAgentHeartbeats = async (req, res) => {
  const heartbeats = await AgentHeartbeat.find({ _org_id: req.orgId })
    .sort({ receivedAt: -1 })
    .limit(100);

  return res.json({
    data: heartbeats,
    total: heartbeats.length,
  });
};

module.exports = {
  createAgentAsset,
  recordHeartbeat,
  listAgentHeartbeats,
};
