const { normalizeEvent } = require("../utils/eventNormalizer");

class AuthCollector {
  collect(payload = {}) {
    return normalizeEvent({
      message: payload.message || "Authentication activity observed",
      level: payload.level || "info",
      source: "host",
      eventType: payload.eventType || "auth.login",
      ip: payload.ip,
      metadata: {
        sensorType: "host",
        host: {
          userName: payload.userName || null,
          loginSuccess:
            payload.loginSuccess === undefined ? undefined : Boolean(payload.loginSuccess),
        },
        ...payload.metadata,
      },
    });
  }
}

module.exports = AuthCollector;
