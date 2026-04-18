require("dotenv").config();

const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const { Tail } = require("tail");
const winston = require("winston");
const { parseFastAlertLine, parseEveJsonLine } = require("./snort-parsers");

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => (
      `${timestamp} [${level.toUpperCase()}] ${message}`
    ))
  ),
  transports: [
    new winston.transports.File({ filename: "agent-error.log", level: "error" }),
    new winston.transports.File({ filename: "agent-combined.log" }),
    new winston.transports.Console(),
  ],
});

const splitList = (value) =>
  String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

const config = {
  apiUrl: process.env.THREATLENS_API_URL || "http://localhost:5000",
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "",
  assetId: process.env.ASSET_ID || "agent-001",
  agentMode: (process.env.AGENT_MODE || "snort").trim().toLowerCase(),
  batchSize: Number.parseInt(process.env.BATCH_SIZE || "20", 10),
  batchTimeoutMs: Number.parseInt(process.env.BATCH_TIMEOUT_MS || "5000", 10),
  healthCheckIntervalMs: Number.parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || "60000", 10),
  maxRetries: 3,
  snortFastLogPaths: splitList(
    process.env.SNORT_FAST_LOG_PATHS || process.env.SNORT_FAST_LOG_PATH || process.env.SNORT_ALERT_FILE || ""
  ),
  snortJsonLogPaths: splitList(
    process.env.SNORT_EVE_JSON_PATHS || process.env.SNORT_EVE_JSON_PATH || ""
  ),
};

class APIClient {
  constructor(runtimeConfig) {
    this.apiKey = runtimeConfig.apiKey;
    this.apiSecret = runtimeConfig.apiSecret;
    this.assetId = runtimeConfig.assetId;
    this.maxRetries = runtimeConfig.maxRetries;

    this.client = axios.create({
      baseURL: runtimeConfig.apiUrl,
      timeout: 10000,
    });
  }

  async submitLogs(logs, attempt = 1) {
    try {
      if (!this.apiKey || !this.apiSecret) {
        logger.error("Missing THREATLENS_API_KEY or THREATLENS_API_SECRET");
        return false;
      }

      const payload = { logs };
      const body = JSON.stringify(payload);
      const timestamp = Date.now().toString();
      const signature = crypto
        .createHmac("sha256", this.apiSecret)
        .update(`${timestamp}.${body}`)
        .digest("hex");

      logger.info(`Sending ${logs.length} live log(s) to ThreatLens (attempt ${attempt})`);

      const response = await this.client.post("/api/logs/ingest", payload, {
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.apiKey,
          "x-api-secret": this.apiSecret,
          "x-timestamp": timestamp,
          "x-signature": signature,
          "x-asset-id": this.assetId,
        },
      });

      logger.info(`Submit success: ${response.status}`);
      return true;
    } catch (error) {
      if (error.response) {
        logger.error(`${error.response.status}: ${JSON.stringify(error.response.data)}`);

        if (error.response.status === 401) {
          logger.error("Unauthorized agent request. Refresh backend/agent credentials.");
          return false;
        }
      } else {
        logger.error(`Network error: ${error.message}`);
      }

      if (attempt < this.maxRetries) {
        logger.warn(`Retrying submit (${attempt + 1})`);
        return this.submitLogs(logs, attempt + 1);
      }

      logger.error("Submit failed after max retries");
      return false;
    }
  }

  async healthCheck() {
    try {
      await this.client.get("/health");
      return true;
    } catch (error) {
      logger.warn("Backend health check failed");
      return false;
    }
  }
}

class SnortLogCollector {
  constructor(runtimeConfig, onEvent) {
    this.onEvent = onEvent;
    this.watchers = [];
    this.fastLogPaths = runtimeConfig.snortFastLogPaths;
    this.jsonLogPaths = runtimeConfig.snortJsonLogPaths;
  }

  watchFile(filePath, parser, label) {
    if (!fs.existsSync(filePath)) {
      logger.warn(`${label} file not found: ${filePath}`);
      return;
    }

    const watcher = new Tail(filePath, {
      fromBeginning: false,
      fsWatchOptions: { interval: 1000 },
      useWatchFile: true,
    });

    watcher.on("line", (line) => {
      const parsed = parser(line);
      if (!parsed) {
        return;
      }

      this.onEvent(parsed);
    });

    watcher.on("error", (error) => {
      logger.error(`Tail error for ${filePath}: ${error.message}`);
    });

    this.watchers.push(watcher);
    logger.info(`Watching ${label} file: ${filePath}`);
  }

  start() {
    this.fastLogPaths.forEach((filePath) => {
      this.watchFile(filePath, parseFastAlertLine, "Snort fast alert");
    });

    this.jsonLogPaths.forEach((filePath) => {
      this.watchFile(filePath, parseEveJsonLine, "Snort EVE JSON");
    });

    if (this.watchers.length === 0) {
      logger.warn("No Snort log files configured. Set SNORT_FAST_LOG_PATH or SNORT_EVE_JSON_PATH.");
    }
  }

  stop() {
    this.watchers.forEach((watcher) => watcher.unwatch());
    this.watchers = [];
  }
}

class ThreatLensAgent {
  constructor(runtimeConfig) {
    this.apiClient = new APIClient(runtimeConfig);
    this.mode = runtimeConfig.agentMode;
    this.batchSize = runtimeConfig.batchSize;
    this.batchTimeoutMs = runtimeConfig.batchTimeoutMs;
    this.healthCheckIntervalMs = runtimeConfig.healthCheckIntervalMs;
    this.buffer = [];
    this.flushTimer = null;
    this.healthTimer = null;
    this.collector = new SnortLogCollector(runtimeConfig, (event) => this.enqueueEvent(event));
  }

  enqueueEvent(event) {
    this.buffer.push(event);
    logger.info(`Live Snort event buffered: ${event.message} (buffer: ${this.buffer.length})`);
    this.scheduleFlush();

    if (this.buffer.length >= this.batchSize) {
      if (this.flushTimer) {
        clearTimeout(this.flushTimer);
        this.flushTimer = null;
      }

      void this.flushBuffer();
    }
  }

  async flushBuffer() {
    if (this.buffer.length === 0) {
      return;
    }

    const logsToSend = [...this.buffer];
    this.buffer = [];

    const success = await this.apiClient.submitLogs(logsToSend);
    if (!success) {
      logger.warn("Restoring failed batch to buffer");
      this.buffer.unshift(...logsToSend);
    }
  }

  scheduleFlush() {
    if (this.flushTimer) {
      return;
    }

    this.flushTimer = setTimeout(async () => {
      this.flushTimer = null;
      await this.flushBuffer();
    }, this.batchTimeoutMs);
  }

  async start() {
    logger.info(`ThreatLens Agent starting in ${this.mode} mode`);

    const healthy = await this.apiClient.healthCheck();
    if (healthy) {
      logger.info("Backend connected");
    } else {
      logger.warn("Backend not reachable at startup");
    }

    if (this.mode !== "snort") {
      logger.warn(`Unsupported AGENT_MODE "${this.mode}". Only "snort" is enabled in this build.`);
      return;
    }

    this.collector.start();

    this.healthTimer = setInterval(async () => {
      const healthyNow = await this.apiClient.healthCheck();
      if (healthyNow) {
        logger.info("Backend heartbeat ok");
      }
    }, this.healthCheckIntervalMs);

    process.on("SIGINT", async () => {
      logger.info("Shutting down agent");
      if (this.flushTimer) {
        clearTimeout(this.flushTimer);
      }
      if (this.healthTimer) {
        clearInterval(this.healthTimer);
      }
      this.collector.stop();
      await this.flushBuffer();
      process.exit();
    });

    logger.info("Agent running and waiting for live Snort events");
  }
}

(async () => {
  try {
    const agent = new ThreatLensAgent(config);
    await agent.start();
  } catch (error) {
    logger.error(`Agent crashed: ${error.message}`);
  }
})();
