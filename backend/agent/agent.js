require("dotenv").config();

const fs = require("fs");
const { v4: uuidv4 } = require("uuid");
const axios = require("axios");
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

logger.add(new winston.transports.Console({
  format: winston.format.simple()
}));

/* ================= CONFIG ================= */

const config = {
  apiUrl: process.env.THREATLENS_API_URL || "http://localhost:5000",
  apiKey: process.env.THREATLENS_API_KEY,
  assetId: process.env.ASSET_ID || "default-asset",
  batchSize: parseInt(process.env.BATCH_SIZE || "50"),
  batchTimeoutMs: parseInt(process.env.BATCH_TIMEOUT_MS || "10000"),
  healthCheckIntervalMs: parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || "60000")
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
    this.client = axios.create({
      baseURL: apiUrl,
      timeout: 10000
    });

    this.apiKey = apiKey;
  }

  async submitEvents(events, assetId) {
    try {
      const response = await this.client.post(
        "/api/ingest/v1/ingest",
        { events },
        {
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": this.apiKey,
            "X-Asset-ID": assetId
          }
        }
      );

      logger.info(`✅ Submitted ${events.length} events (status ${response.status})`);
      return true;

    } catch (error) {
      if (error.response) {
        logger.error(`❌ Submit failed ${error.response.status}`);
      } else {
        logger.error(`❌ Submit error: ${error.message}`);
      }
      return false;
    }
  }

  async healthCheck() {
    try {
      const response = await this.client.get("/api/ingest/v1/health");
      return response.data.status === "ok";
    } catch {
      return false;
    }
  }
}

/* ================= COLLECTOR ================= */

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
      source: "system",
      asset_id: this.assetId,
      metadata: { example: uuidv4() }
    };
  }
}

/* ================= MAIN AGENT ================= */

class ThreatLensAgent {
  constructor(config) {
    this.apiClient = new APIClient(config.apiUrl, config.apiKey);
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
    if (!healthy) {
      logger.warn("⚠ Backend not healthy");
    }

    setInterval(() => {
      const event = this.collector.collectRandomEvent();
      this.buffer.add(event);
    }, 1000);

    logger.info("✅ Agent running");
  }

  async submit(events) {
    await this.apiClient.submitEvents(events, this.collector.assetId);
  }
}

/* ================= ENTRY ================= */

(async () => {
  const agent = new ThreatLensAgent(config);
  await agent.start();
})();