require("dotenv").config();

const fs = require("fs");
const logger = require("./utils/logger");
const { ThreatLensAPIClient, normalizeApiRoot } = require("./services/apiClient");
const { parseFastAlertLine, parseEveJsonLine } = require("./snort-parser");
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
  json: ["C:\\snort\\log\\eve.json", "C:\\Snort\\log\\eve.json"],
};

const DEFAULT_LINUX_SNORT_PATHS = {
  fast: [
    "/var/log/snort/snort.alert.fast",
    "/var/log/snort/alert_fast.txt",
    "/var/log/snort/alert",
  ],
  json: ["/var/log/snort/eve.json"],
};

const resolvePaths = (configured, fallback) => {
  if (configured.length > 0) return configured;
  return fallback.filter((candidate) => fs.existsSync(candidate));
};

const platformFallbacks =
  process.platform === "win32"
    ? DEFAULT_WINDOWS_SNORT_PATHS
    : DEFAULT_LINUX_SNORT_PATHS;

const config = {
  apiUrl: normalizeApiRoot(
    process.env.THREATLENS_API_URL || "http://localhost:5001"
  ),
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "",
  assetId: process.env.ASSET_ID || "agent-001",

  batchSize: Number(process.env.BATCH_SIZE || 20),
  batchTimeoutMs: Number(
    process.env.BATCH_TIMEOUT_MS || process.env.FLUSH_INTERVAL_MS || 5000
  ),
  healthCheckIntervalMs: Number(process.env.HEALTH_CHECK_INTERVAL_MS || 60000),
  heartbeatIntervalMs: Number(
    process.env.HEARTBEAT_INTERVAL_MS || process.env.SYSTEM_INTERVAL_MS || 15000
  ),
  maxRetries: Number(process.env.MAX_RETRIES || 3),
  maxBufferSize: Number(process.env.MAX_BUFFER_SIZE || 5000),
  filePollIntervalMs: Number(process.env.FILE_POLL_INTERVAL_MS || 2000),

  snortFastLogPaths: resolvePaths(
    splitList(
      process.env.SNORT_FAST_LOG_PATHS || process.env.SNORT_FAST_LOG_PATH || ""
    ),
    platformFallbacks.fast
  ),

  snortJsonLogPaths: resolvePaths(
    splitList(
      process.env.SNORT_EVE_JSON_PATHS || process.env.SNORT_EVE_JSON_PATH || ""
    ),
    platformFallbacks.json
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
    this.running = false;
  }

  enqueue(event) {
    if (!event) return;

    const enrichedEvent = {
      ...event,
      assetId: this.config.assetId,
      agentType: "nids",
      collector: "realtime-agent",
      receivedAt: new Date().toISOString(),
    };

    if (this.buffer.length >= this.config.maxBufferSize) {
      this.buffer.shift();
      logger.warn(
        `Realtime IDS buffer limit reached. Dropping oldest event. Limit: ${this.config.maxBufferSize}`
      );
    }

    this.buffer.push(enrichedEvent);

    logger.info(
      `Buffered Snort event: ${enrichedEvent.message || "Unknown"} (${this.buffer.length})`
    );

    if (this.buffer.length >= this.config.batchSize) {
      void this.flush();
    }
  }

  async flush() {
    if (this.flushing || this.buffer.length === 0) return;

    this.flushing = true;

    const batch = [...this.buffer];
    this.buffer = [];

    try {
      const result = await this.apiClient.submitLogs(batch);

      logger.info(
        `Submitted ${batch.length} Snort event(s). Inserted: ${
          result?.inserted ?? result?.count ?? "n/a"
        }`
      );
    } catch (error) {
      logger.error(`Realtime IDS submit failed: ${error.message}`);

      this.buffer.unshift(...batch);

      if (this.buffer.length > this.config.maxBufferSize) {
        this.buffer = this.buffer.slice(0, this.config.maxBufferSize);
      }
    } finally {
      this.flushing = false;
    }
  }

  tailFile(filePath, parser) {
    let lastSize = 0;

    try {
      if (fs.existsSync(filePath)) {
        lastSize = fs.statSync(filePath).size;
      }
    } catch (error) {
      logger.warn(`Unable to read initial size for ${filePath}: ${error.message}`);
    }

    const timer = setInterval(() => {
      try {
        if (!fs.existsSync(filePath)) return;

        const currentSize = fs.statSync(filePath).size;

        if (currentSize < lastSize) {
          logger.warn(`Detected log rotation/truncation for ${filePath}`);
          lastSize = 0;
        }

        if (currentSize === lastSize) return;

        const stream = fs.createReadStream(filePath, {
          start: lastSize,
          end: currentSize - 1,
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
              } else {
                logger.warn(`Unparsed Snort line: ${line.slice(0, 160)}`);
              }
            });
        });

        stream.on("error", (error) => {
          logger.warn(`Stream error for ${filePath}: ${error.message}`);
        });

        lastSize = currentSize;
      } catch (error) {
        logger.warn(`File tail warning for ${filePath}: ${error.message}`);
      }
    }, this.config.filePollIntervalMs);

    this.watchers.push(timer);
    logger.info(`Watching Snort file: ${filePath}`);
  }

  async sendHeartbeat() {
    const heartbeat = this.heartbeatCollector.collect({
      assetId: this.config.assetId,
      agentType: "nids",
      agentVersion: process.env.AGENT_VERSION || "1.1.0",
      telemetryTypes: ["snort-fast", "snort-eve-json"],
      queueDepth: this.buffer.length,
      metadata: {
        collector: "realtime-agent",
        mode: "snort",
        fastPaths: this.config.snortFastLogPaths,
        jsonPaths: this.config.snortJsonLogPaths,
        watchedFiles:
          this.config.snortFastLogPaths.length +
          this.config.snortJsonLogPaths.length,
      },
    });

    try {
      await this.apiClient.sendHeartbeat(heartbeat);
      logger.info("Realtime Snort agent heartbeat sent");
    } catch (error) {
      logger.warn(`Realtime Snort agent heartbeat failed: ${error.message}`);
    }
  }

  async start() {
    this.running = true;

    logger.info("ThreatLens Realtime Snort Agent Starting");
    logger.info(`Backend URL: ${this.config.apiUrl}`);
    logger.info(`Asset ID: ${this.config.assetId}`);

    if (
      this.config.snortFastLogPaths.length === 0 &&
      this.config.snortJsonLogPaths.length === 0
    ) {
      logger.warn(
        "No Snort log files found. Set SNORT_FAST_LOG_PATH or SNORT_EVE_JSON_PATH in agent/.env"
      );
    }

    try {
      await this.apiClient.healthCheck();
      logger.info("Backend connected");
    } catch (error) {
      logger.warn(`Backend health check failed: ${error.message}`);
    }

    this.config.snortFastLogPaths.forEach((filePath) => {
      this.tailFile(filePath, parseFastAlertLine);
    });

    this.config.snortJsonLogPaths.forEach((filePath) => {
      this.tailFile(filePath, parseEveJsonLine);
    });

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
          logger.info("Realtime backend health ok");
        } catch (error) {
          logger.warn(`Realtime backend health failed: ${error.message}`);
        }
      }, this.config.healthCheckIntervalMs)
    );

    await this.sendHeartbeat();

    const stop = async () => {
      if (!this.running) return;

      this.running = false;
      logger.info("Stopping realtime Snort agent");

      this.timers.forEach((timer) => clearInterval(timer));
      this.watchers.forEach((watcher) => clearInterval(watcher));

      await this.flush();

      process.exit(0);
    };

    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);

    logger.info("Realtime Snort agent running");
  }
}

(async () => {
  try {
    const agent = new RealtimeAgent(config);
    await agent.start();
  } catch (error) {
    logger.error(`Realtime Snort agent crashed: ${error.message}`);
    process.exit(1);
  }
})();