require("dotenv").config();

const fs = require("fs");
const logger = require("./utils/logger");
const { ThreatLensAPIClient, normalizeApiRoot } = require("./services/apiClient");
const { parseFastAlertLine, parseEveJsonLine } = require("./snort-parsers");
const HeartbeatCollector = require("./collectors/heartbeat.collector");

const splitList = (value = "") =>
  String(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

const DEFAULT_WINDOWS_SNORT_PATHS = {
  fast: [
    "C:\\snort\\log\\alert_fast.txt",
    "C:\\Snort\\log\\alert_fast.txt",
    "C:\\snort\\log\\alert",
    "C:\\Snort\\log\\alert",
  ],
  json: [
    "C:\\snort\\log\\eve.json",
    "C:\\Snort\\log\\eve.json",
  ],
};

const resolvePaths = (configured, fallback) => {
  if (configured.length > 0) {
    return configured;
  }

  return fallback.filter((candidate) => fs.existsSync(candidate));
};

const config = {
  apiUrl: normalizeApiRoot(process.env.THREATLENS_API_URL || "http://localhost:5000"),
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "",
  assetId: process.env.ASSET_ID || "agent-001",
  batchSize: Number(process.env.BATCH_SIZE || 20),
  batchTimeoutMs: Number(process.env.BATCH_TIMEOUT_MS || 5000),
  healthCheckIntervalMs: Number(process.env.HEALTH_CHECK_INTERVAL_MS || 60000),
  heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS || 15000),
  maxRetries: Number(process.env.MAX_RETRIES || 3),
  snortFastLogPaths: resolvePaths(
    splitList(process.env.SNORT_FAST_LOG_PATHS || process.env.SNORT_FAST_LOG_PATH || ""),
    DEFAULT_WINDOWS_SNORT_PATHS.fast
  ),
  snortJsonLogPaths: resolvePaths(
    splitList(process.env.SNORT_EVE_JSON_PATHS || process.env.SNORT_EVE_JSON_PATH || ""),
    DEFAULT_WINDOWS_SNORT_PATHS.json
  ),
};

class RealtimeAgent {
  constructor(runtimeConfig) {
    this.config = runtimeConfig;
    this.apiClient = new ThreatLensAPIClient(runtimeConfig);
    this.heartbeatCollector = new HeartbeatCollector();
    this.buffer = [];
    this.timers = [];
    this.watchers = [];
    this.flushing = false;
  }

  enqueue(event) {
    this.buffer.push(event);
    logger.info(`Buffered realtime IDS event: ${event.message} (${this.buffer.length})`);

    if (this.buffer.length >= this.config.batchSize) {
      void this.flush();
    }
  }

  async flush() {
    if (this.flushing || this.buffer.length === 0) {
      return;
    }

    this.flushing = true;
    const batch = [...this.buffer];
    this.buffer = [];

    try {
      const result = await this.apiClient.submitLogs(batch);
      logger.info(
        `Submitted ${batch.length} realtime IDS event(s). Inserted: ${result?.inserted ?? "n/a"}`
      );
    } catch (error) {
      logger.error(
        `Realtime IDS submit failed: ${
          error.response
            ? `${error.response.status} ${JSON.stringify(error.response.data)}`
            : error.message
        }`
      );
      this.buffer.unshift(...batch);
    } finally {
      this.flushing = false;
    }
  }

  tailFile(filePath, parser) {
    let lastSize = fs.existsSync(filePath) ? fs.statSync(filePath).size : 0;

    const timer = setInterval(() => {
      try {
        if (!fs.existsSync(filePath)) {
          return;
        }

        const currentSize = fs.statSync(filePath).size;
        if (currentSize < lastSize) {
          lastSize = 0;
        }

        if (currentSize === lastSize) {
          return;
        }

        const stream = fs.createReadStream(filePath, {
          start: lastSize,
          end: currentSize,
          encoding: "utf8",
        });

        let data = "";
        stream.on("data", (chunk) => {
          data += chunk;
        });

        stream.on("end", () => {
          data
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
            .forEach((line) => {
              const parsed = parser(line);
              if (parsed) {
                this.enqueue(parsed);
              }
            });
        });

        lastSize = currentSize;
      } catch (error) {
        logger.warn(`File tail warning for ${filePath}: ${error.message}`);
      }
    }, 2000);

    this.watchers.push(timer);
    logger.info(`Watching realtime IDS file: ${filePath}`);
  }

  async sendHeartbeat() {
    const heartbeat = this.heartbeatCollector.collect({
      assetId: this.config.assetId,
      agentType: "nids",
      agentVersion: "1.1.0",
      telemetryTypes: ["snort", "suricata"],
      queueDepth: this.buffer.length,
      metadata: {
        fastPaths: this.config.snortFastLogPaths,
        jsonPaths: this.config.snortJsonLogPaths,
      },
    });

    try {
      await this.apiClient.sendHeartbeat(heartbeat);
      logger.info("Realtime agent heartbeat sent");
    } catch (error) {
      logger.warn(
        `Realtime agent heartbeat failed: ${
          error.response
            ? `${error.response.status} ${JSON.stringify(error.response.data)}`
            : error.message
        }`
      );
    }
  }

  async start() {
    logger.info("ThreatLens Realtime Agent Starting");
    logger.info(`Backend URL: ${this.config.apiUrl}`);
    logger.info(`Asset ID: ${this.config.assetId}`);

    try {
      await this.apiClient.healthCheck();
      logger.info("Backend connected");
    } catch (error) {
      logger.warn(
        `Backend health check failed: ${
          error.response
            ? `${error.response.status} ${JSON.stringify(error.response.data)}`
            : error.message
        }`
      );
    }

    this.config.snortFastLogPaths.forEach((filePath) =>
      this.tailFile(filePath, parseFastAlertLine)
    );
    this.config.snortJsonLogPaths.forEach((filePath) =>
      this.tailFile(filePath, parseEveJsonLine)
    );

    this.timers.push(
      setInterval(() => {
        void this.flush();
      }, this.config.batchTimeoutMs)
    );

    this.timers.push(
      setInterval(() => {
        void this.sendHeartbeat();
      }, this.config.heartbeatIntervalMs)
    );

    this.timers.push(
      setInterval(async () => {
        try {
          await this.apiClient.healthCheck();
          logger.info("Realtime backend heartbeat ok");
        } catch (error) {
          logger.warn(`Realtime backend heartbeat failed: ${error.message}`);
        }
      }, this.config.healthCheckIntervalMs)
    );

    await this.sendHeartbeat();

    process.on("SIGINT", async () => {
      logger.info("Stopping realtime agent");
      this.timers.forEach((timer) => clearInterval(timer));
      this.watchers.forEach((watcher) => clearInterval(watcher));
      await this.flush();
      process.exit(0);
    });

    logger.info("Realtime agent running");
  }
}

(async () => {
  try {
    const agent = new RealtimeAgent(config);
    await agent.start();
  } catch (error) {
    logger.error(`Realtime agent crashed: ${error.message}`);
  }
})();
