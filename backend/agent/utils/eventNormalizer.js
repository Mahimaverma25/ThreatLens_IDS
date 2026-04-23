const { v4: uuidv4 } = require("uuid");
const { getOsInfo } = require("./osInfo");

const normalizeEvent = (event = {}, overrides = {}) => {
  const osInfo = getOsInfo();
  const metadata =
    event.metadata && typeof event.metadata === "object" ? event.metadata : {};

  return {
    message: event.message || "Agent event",
    level: event.level || "info",
    source: event.source || "agent",
    eventType: event.eventType || "agent.event",
    ip: event.ip || osInfo.ip,
    timestamp: event.timestamp || new Date().toISOString(),
    metadata: {
      uuid: metadata.uuid || uuidv4(),
      sensorType: metadata.sensorType || "host",
      hostname: metadata.hostname || osInfo.hostname,
      platform: metadata.platform || osInfo.platform,
      ...metadata,
    },
    ...overrides,
  };
};

module.exports = {
  normalizeEvent,
};
