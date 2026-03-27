require("dotenv").config();

const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");

/* ================= LOGGER ================= */

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "agent-error.log", level: "error" }),
    new winston.transports.File({ filename: "agent-combined.log" })
  ]
});

logger.add(
  new winston.transports.Console({
    format: winston.format.simple()
  })
);

/* ================= CONFIG ================= */

const config = {
  apiUrl: process.env.THREATLENS_API_URL || "http://localhost:5000",
  apiKey: process.env.THREATLENS_API_KEY,
  assetId: process.env.ASSET_ID || "default-asset",

  batchSize: parseInt(process.env.BATCH_SIZE || "50"),
  batchTimeoutMs: parseInt(process.env.BATCH_TIMEOUT_MS || "10000"),

  healthCheckIntervalMs: parseInt(
    process.env.HEALTH_CHECK_INTERVAL_MS || "60000"
  )
};

if (!config.apiKey) {
  console.error("❌ THREATLENS_API_KEY is required in .env");
  process.exit(1);
}

/* ================= EVENT BUFFER ================= */

class EventBuffer {
  constructor(batchSize, timeoutMs, onBatchReady) {
    this.events = [];
    this.batchSize = batchSize;
    this.timeoutMs = timeoutMs;
    this.onBatchReady = onBatchReady;

    setInterval(() => {
      this.flush();
    }, this.timeoutMs);
  }

  add(event) {
    this.events.push(event);

    if (this.events.length >= this.batchSize) {
      this.flush();
    }
  }

  flush() {
    if (this.events.length === 0) return;

    const batch = this.events.splice(0);
    this.onBatchReady(batch);
  }
}

/* ================= API CLIENT ================= */

class APIClient {
  constructor(apiUrl, apiKey) {
    this.apiKey = apiKey;

    this.client = axios.create({
      baseURL: apiUrl,
      timeout: 10000
    });
  }

  async submitEvents(events, assetId) {
    try {
      const payload = {
        logs: events.map((e) => ({
          message: `Event: ${e.event_type}`,
          level: e.severity || "info",
          source: e.source || "agent",
          eventType: e.event_type,
          metadata: e.metadata || {},
          asset_id: assetId,
          timestamp: e.timestamp
        }))
      };

      const response = await this.client.post(
        "/api/logs/ingest",
        payload,
        {
          headers: {
            "Content-Type": "application/json",
            "X-api-Key": this.apiKey,
            "x-org-id": process.env.ORG_ID || "default-org"
          }
        }
      );

      logger.info(
        `✅ Submitted ${events.length} events (status ${response.status})`
      );

      return true;
    } catch (error) {
      if (error.response) {
        logger.error(`❌ Submit failed ${error.response.status}`);
        logger.error(
          `❌ Backend response: ${JSON.stringify(error.response.data)}`
        );
      } else {
        logger.error(`❌ Network error: ${error.message}`);
      }

      return false;
    }
  }

  // ✅ FIXED HEALTH CHECK (NO AUTH REQUIRED)
  async healthCheck() {
    try {
      await this.client.get("/"); // 👈 simple ping

      return true;
    } catch (error) {
      logger.warn("⚠ Backend health check failed");
      return false;
    }
  }
}

/* ================= EVENT COLLECTOR ================= */

class EventCollector {
  constructor(assetId) {
    this.assetId = assetId;
    this.counter = 0;
  }

  collectRandomEvent() {
    return {
      event_id: `${this.assetId}-${++this.counter}-${Date.now()}`,
      timestamp: new Date().toISOString(),
      event_type: "system_event",
      severity: "low",
      source: "agent",
      asset_id: this.assetId,

      metadata: {
        uuid: uuidv4(),
        example: "heartbeat"
      }
    };
  }
}

/* ================= MAIN AGENT ================= */

class ThreatLensAgent {
  constructor(config) {
    this.apiClient = new APIClient(
      config.apiUrl,
      config.apiKey
    );

    this.collector = new EventCollector(config.assetId);

    this.buffer = new EventBuffer(
      config.batchSize,
      config.batchTimeoutMs,
      (batch) => this.submit(batch)
    );
  }

  async start() {
    logger.info("🚀 ThreatLens Agent Starting...");

    const healthy = await this.apiClient.healthCheck();

    if (healthy) {
      logger.info("✅ Backend connected");
    } else {
      logger.warn("⚠ Backend not reachable");
    }

    setInterval(() => {
      const event = this.collector.collectRandomEvent();
      this.buffer.add(event);
    }, 1000);

    logger.info("✅ Agent running...");
  }

  async submit(events) {
    await this.apiClient.submitEvents(events, this.collector.assetId);
  }
}

/* ================= ENTRY ================= */

(async () => {
  try {
    const agent = new ThreatLensAgent(config);
    await agent.start();
  } catch (err) {
    logger.error("❌ Agent crashed: " + err.message);
  }
})();