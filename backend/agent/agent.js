require("dotenv").config();

const axios = require("axios");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");

/* ================= LOGGER ================= */

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({ filename: "agent-error.log", level: "error" }),
    new winston.transports.File({ filename: "agent-combined.log" }),
    new winston.transports.Console()
  ]
});

/* ================= CONFIG ================= */

const config = {
  apiUrl: process.env.THREATLENS_API_URL || "http://localhost:5000", // ✅ FIXED
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "tlk_secret_dev",
  assetId: process.env.ASSET_ID || "default-asset",

  intervalMs: 2000,
  batchSize : 5, // sends logs in batch
  maxRetries: 3
};

/* ================= API CLIENT ================= */

class APIClient {
  constructor(config) {
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.assetId = config.assetId;
    this.maxRetries = config.maxRetries;

    this.client = axios.create({
      baseURL: config.apiUrl,
      timeout: 10000
    });
  }

  async submitLogs(logs, attempt = 1) {
    try {
      if (!this.apiKey || !this.apiSecret) {
        logger.error("❌ Missing THREATLENS_API_KEY or THREATLENS_API_SECRET");
        return false;
      }

      // ✅ MATCH BACKEND FORMAT
      const payload = { logs }; // CRITICAL: wrap in "logs" key to match backend expectation
      const body = JSON.stringify(payload);
      const timestamp = Date.now().toString();
      const signature = crypto
        .createHmac("sha256", this.apiSecret)
        .update(`${timestamp}.${body}`)
        .digest("hex");

      logger.info(`📤 Sending ${logs.length} logs (attempt ${attempt})`);

      const response = await this.client.post(
        "/api/logs/ingest",
        payload,
        {
          headers: {
            "Content-Type": "application/json",
            "x-api-key": this.apiKey,
            "x-api-secret": this.apiSecret,
            "x-timestamp": timestamp,
            "x-signature": signature,
            "x-asset-id": this.assetId,
          }
        }
      );

      logger.info(`✅ Success: ${response.status}`);
      return true;

    } catch (error) {
      if (error.response) {
        logger.error(`❌ ${error.response.status}: ${JSON.stringify(error.response.data)}`);

        // 🚨 AUTH ERROR (NO RETRY)
        if (error.response.status === 401) {
          logger.error("🚨 Unauthorized! Check API KEY or ORG ID");
          return false;
        }
      } else {
        logger.error(`❌ Network error: ${error.message}`);
      }

      // 🔁 RETRY LOGIC
      if (attempt < this.maxRetries) {
        logger.warn(`🔁 Retrying... (${attempt + 1})`);
        return this.submitLogs(logs, attempt + 1);
      }

      logger.error("❌ Failed after max retries");
      return false;
    }
  }

  async healthCheck() {
    try {
      await this.client.get("/health");
      return true;
    } catch (err) {
      logger.warn("⚠ Health check failed");
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

  collectEvent() {
    this.counter++;

    return {
      message: "SQL Injection attempt detected",
      level: "high",
      source: "agent",
      eventType: "SQL Injection",
      ip: "127.0.0.1",
      timestamp: new Date().toISOString(),

      metadata: {
        uuid: uuidv4(),
        asset_id: this.assetId,
        count: this.counter
      }
    };
  }
}

/* ================= MAIN AGENT ================= */

class ThreatLensAgent {
  constructor(config) {
    this.apiClient = new APIClient(config);
    this.collector = new EventCollector(config.assetId);

    this.intervalMs = config.intervalMs;
    this.batchSize = config.batchSize;

    this.buffer = [];
  }

  async start() {
    logger.info("🚀 ThreatLens Agent Starting...");

    const healthy = await this.apiClient.healthCheck();

    if (healthy) {
      logger.info("✅ Backend connected");
    } else {
      logger.warn("⚠ Backend not reachable");
    }

    setInterval(async () => {
      try {
        const event = this.collector.collectEvent();
        this.buffer.push(event);

        logger.info(`📥 Event collected (buffer: ${this.buffer.length})`);

        if (this.buffer.length >= this.batchSize) {
          const logsToSend = [...this.buffer];
          this.buffer = [];

          const success = await this.apiClient.submitLogs(logsToSend);

          // 🔁 restore logs if failed
          if (!success) {
            logger.warn("⚠ Restoring logs to buffer");
            this.buffer.unshift(...logsToSend);
          }
        }

      } catch (err) {
        logger.error("❌ Error in interval: " + err.message);
      }
    }, this.intervalMs);

    // 🛑 graceful shutdown
    process.on("SIGINT", async () => {
      logger.info("🛑 Shutting down... sending remaining logs");

      if (this.buffer.length > 0) {
        await this.apiClient.submitLogs(this.buffer);
      }

      process.exit();
    });

    logger.info("✅ Agent running...");
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