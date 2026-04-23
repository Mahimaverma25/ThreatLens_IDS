const { normalizeEvent } = require("../utils/eventNormalizer");

class ProcessCollector {
  collect(payload = {}) {
    return normalizeEvent({
      message: payload.message || "Process execution observed",
      level: payload.level || "info",
      source: "host",
      eventType: payload.eventType || "process.start",
      ip: payload.ip,
      metadata: {
        sensorType: "host",
        host: {
          processName: payload.processName || null,
          commandLine: payload.commandLine || null,
          pid: payload.pid ?? null,
          parentPid: payload.parentPid ?? null,
          userName: payload.userName || null,
          elevated:
            payload.elevated === undefined ? undefined : Boolean(payload.elevated),
        },
        ...payload.metadata,
      },
    });
  }
}

module.exports = ProcessCollector;
