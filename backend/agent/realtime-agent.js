require("dotenv").config();

const axios = require("axios");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");

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

const config = {
  apiUrl: process.env.THREATLENS_API_URL || "http://localhost:5000",
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "",
  assetId: process.env.ASSET_ID || "agent-001",
  intervalMs: Number.parseInt(process.env.EVENT_INTERVAL_MS || "2000", 10),
  batchSize: Number.parseInt(process.env.BATCH_SIZE || "20", 10),
  batchTimeoutMs: Number.parseInt(process.env.BATCH_TIMEOUT_MS || "10000", 10),
  healthCheckIntervalMs: Number.parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || "60000", 10),
  maxRetries: 3,
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

      logger.info(`Sending ${logs.length} logs (attempt ${attempt})`);

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

class EventCollector {
  constructor(assetId) {
    this.assetId = assetId;
    this.counter = 0;
    this.countries = ["US", "IN", "DE", "SG", "AU", "BR", "JP", "GB", "NL", "CA"];
    this.endpoints = [
      "/api/auth/login",
      "/api/logs",
      "/api/alerts",
      "/dashboard",
      "/reports/export",
      "/admin/users",
    ];
  }

  pick(values) {
    return values[Math.floor(Math.random() * values.length)];
  }

  randomIp() {
    return `192.168.${Math.floor(Math.random() * 6) + 1}.${Math.floor(Math.random() * 254) + 1}`;
  }

  buildBaseMetadata() {
    return {
      uuid: uuidv4(),
      asset_id: this.assetId,
      count: this.counter,
      sourceCountry: this.pick(this.countries),
      destinationCountry: this.pick(this.countries),
    };
  }

  buildRequestEvent() {
    const destinationPort = this.pick([22, 53, 80, 443, 445, 8080, 3306, 3389]);
    const protocol =
      destinationPort === 22
        ? "SSH"
        : destinationPort === 443
          ? "HTTPS"
          : destinationPort === 80 || destinationPort === 8080
            ? "HTTP"
            : destinationPort === 53
              ? "UDP"
              : "TCP";

    const requestRate = Math.floor(Math.random() * 260) + 10;
    const failedAttempts =
      destinationPort === 22 || destinationPort === 443
        ? Math.floor(Math.random() * 10)
        : Math.floor(Math.random() * 4);

    return {
      message: `${protocol} traffic observed on port ${destinationPort}`,
      level: requestRate > 200 || failedAttempts > 6 ? "warn" : "info",
      source: "agent",
      eventType: "request",
      ip: this.randomIp(),
      endpoint: this.pick(this.endpoints),
      timestamp: new Date().toISOString(),
      metadata: {
        ...this.buildBaseMetadata(),
        protocol,
        bytes: Math.floor(Math.random() * 115000) + 1500,
        duration: Number((Math.random() * 20 + 0.2).toFixed(2)),
        destinationPort,
        port: destinationPort,
        requestRate,
        failedAttempts,
        flowCount: Math.floor(Math.random() * 25) + 1,
        uniquePorts: Math.floor(Math.random() * 18) + 1,
        dnsQueries: destinationPort === 53 ? Math.floor(Math.random() * 140) : 0,
        smbWrites: destinationPort === 445 ? Math.floor(Math.random() * 42) : 0,
      },
    };
  }

  buildAuthFailureEvent() {
    return {
      message: "Repeated login failures detected",
      level: "warn",
      source: "agent",
      eventType: "auth.login",
      ip: this.randomIp(),
      timestamp: new Date().toISOString(),
      metadata: {
        ...this.buildBaseMetadata(),
        success: false,
        username: this.pick(["admin", "finance", "ops", "service", "viewer"]),
        failedAttempts: Math.floor(Math.random() * 8) + 3,
      },
    };
  }

  buildMalwareEvent() {
    return {
      message: "Suspicious malware beaconing activity detected",
      level: "error",
      source: "agent",
      eventType: "request",
      ip: this.randomIp(),
      endpoint: "/command-and-control/checkin",
      timestamp: new Date().toISOString(),
      metadata: {
        ...this.buildBaseMetadata(),
        protocol: "HTTPS",
        bytes: Math.floor(Math.random() * 90000) + 25000,
        duration: Number((Math.random() * 24 + 2).toFixed(2)),
        destinationPort: 443,
        port: 443,
        requestRate: Math.floor(Math.random() * 180) + 60,
        failedAttempts: Math.floor(Math.random() * 3),
        flowCount: Math.floor(Math.random() * 18) + 10,
        uniquePorts: Math.floor(Math.random() * 6) + 1,
      },
    };
  }

  collectEvent() {
    this.counter += 1;

    const generator = this.pick([
      () => this.buildRequestEvent(),
      () => this.buildRequestEvent(),
      () => this.buildRequestEvent(),
      () => this.buildAuthFailureEvent(),
      () => this.buildMalwareEvent(),
    ]);

    return generator();
  }
}

class ThreatLensAgent {
  constructor(runtimeConfig) {
    this.apiClient = new APIClient(runtimeConfig);
    this.collector = new EventCollector(runtimeConfig.assetId);
    this.intervalMs = runtimeConfig.intervalMs;
    this.batchSize = runtimeConfig.batchSize;
    this.batchTimeoutMs = runtimeConfig.batchTimeoutMs;
    this.healthCheckIntervalMs = runtimeConfig.healthCheckIntervalMs;
    this.buffer = [];
    this.flushTimer = null;
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
    logger.info("ThreatLens Agent starting");

    const healthy = await this.apiClient.healthCheck();
    if (healthy) {
      logger.info("Backend connected");
    } else {
      logger.warn("Backend not reachable at startup");
    }

    setInterval(async () => {
      try {
        const event = this.collector.collectEvent();
        this.buffer.push(event);
        logger.info(`Event collected (buffer: ${this.buffer.length})`);
        this.scheduleFlush();

        if (this.buffer.length >= this.batchSize) {
          if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
          }
          await this.flushBuffer();
        }
      } catch (error) {
        logger.error(`Error collecting event: ${error.message}`);
      }
    }, this.intervalMs);

    setInterval(async () => {
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
      await this.flushBuffer();
      process.exit();
    });

    logger.info("Agent running");
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
