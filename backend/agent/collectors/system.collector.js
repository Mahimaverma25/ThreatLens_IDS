const os = require("os");
const { normalizeEvent } = require("../utils/eventNormalizer");

class SystemCollector {
  collect(payload = {}) {
    return normalizeEvent({
      message: payload.message || "System telemetry captured",
      level: payload.level || "info",
      source: "host",
      eventType: payload.eventType || "system.health",
      metadata: {
        sensorType: "host",
        system: {
          loadAverage: os.loadavg(),
          freeMemoryBytes: os.freemem(),
          totalMemoryBytes: os.totalmem(),
          uptimeSeconds: os.uptime(),
        },
        ...payload.metadata,
      },
    });
  }
}

module.exports = SystemCollector;
