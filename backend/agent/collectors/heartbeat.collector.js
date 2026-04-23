const os = require("os");
const { getOsInfo } = require("../utils/osInfo");

class HeartbeatCollector {
  collect(payload = {}) {
    const osInfo = getOsInfo();

    return {
      asset_id: payload.assetId || null,
      agent_type: payload.agentType || "node-agent",
      agent_version: payload.agentVersion || "1.0.0",
      hostname: osInfo.hostname,
      host_platform: `${osInfo.platform}-${osInfo.release}`,
      telemetry_types: payload.telemetryTypes || ["host"],
      queue_depth: Number(payload.queueDepth || 0),
      status: payload.status || "online",
      metadata: {
        uptimeSeconds: osInfo.uptimeSeconds,
        totalMemoryBytes: osInfo.totalMemoryBytes,
        freeMemoryBytes: osInfo.freeMemoryBytes,
        loadAverage: os.loadavg(),
        ...payload.metadata,
      },
    };
  }
}

module.exports = HeartbeatCollector;
