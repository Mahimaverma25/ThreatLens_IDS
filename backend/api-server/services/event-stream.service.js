const config = require("../config/env");

const streamState = {
  mode: "memory",
  key: config.redisStreamKey,
  maxLen: config.redisStreamMaxLen,
  connected: false,
  lastPublishedAt: null,
  lastError: null,
  client: null,
  memoryEvents: [],
};

const safeRequireRedis = () => {
  try {
    // Optional dependency: the backend can still run in demo/dev mode without Redis.
    return require("redis");
  } catch (error) {
    return null;
  }
};

const sanitizeValue = (value) => {
  if (value === undefined) {
    return null;
  }

  if (value === null) {
    return null;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value) || typeof value === "object") {
    return JSON.stringify(value);
  }

  return String(value);
};

const appendMemoryEvent = (payload) => {
  streamState.memoryEvents.unshift({
    id: `mem-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    ...payload,
  });

  if (streamState.memoryEvents.length > streamState.maxLen) {
    streamState.memoryEvents.length = streamState.maxLen;
  }
};

const initEventStream = async () => {
  const redis = safeRequireRedis();

  if (!redis || !config.redisUrl) {
    streamState.mode = "memory";
    streamState.connected = false;
    return streamState;
  }

  try {
    const client = redis.createClient({
      url: config.redisUrl,
      socket: {
        reconnectStrategy: (retries) => Math.min(retries * 250, 5000),
      },
    });

    client.on("error", (error) => {
      streamState.lastError = error.message;
      streamState.connected = false;
    });

    client.on("ready", () => {
      streamState.connected = true;
      streamState.lastError = null;
    });

    client.on("end", () => {
      streamState.connected = false;
    });

    await client.connect();

    streamState.client = client;
    streamState.mode = "redis-streams";
    streamState.connected = client.isReady;
    streamState.lastError = null;

    return streamState;
  } catch (error) {
    streamState.mode = "memory";
    streamState.connected = false;
    streamState.lastError = error.message;
    return streamState;
  }
};

const publishEvent = async (eventName, payload = {}) => {
  const envelope = {
    eventName,
    timestamp: new Date().toISOString(),
    payload,
  };

  streamState.lastPublishedAt = envelope.timestamp;

  if (streamState.mode === "redis-streams" && streamState.client?.isReady) {
    try {
      const values = {
        eventName,
        timestamp: envelope.timestamp,
        payload: sanitizeValue(payload),
        organizationId: sanitizeValue(payload.organizationId),
        source: sanitizeValue(payload.source),
      };

      await streamState.client.xAdd(
        streamState.key,
        "*",
        values,
        {
          TRIM: {
            strategy: "MAXLEN",
            strategyModifier: "~",
            threshold: streamState.maxLen,
          },
        }
      );

      streamState.lastError = null;
      return { queued: true, mode: streamState.mode };
    } catch (error) {
      streamState.lastError = error.message;
      streamState.connected = false;
    }
  }

  appendMemoryEvent(envelope);
  return { queued: true, mode: "memory" };
};

const getEventStreamHealth = () => ({
  mode: streamState.mode,
  connected: streamState.connected,
  key: streamState.key,
  bufferedEvents: streamState.memoryEvents.length,
  lastPublishedAt: streamState.lastPublishedAt,
  lastError: streamState.lastError,
});

module.exports = {
  initEventStream,
  publishEvent,
  getEventStreamHealth,
};
