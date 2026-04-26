require("dotenv").config();

const path = require("path");
const logger = require("./utils/logger");
const { ThreatLensAPIClient, normalizeApiRoot } = require("./services/apiClient");
const AuthCollector = require("./collectors/auth.collector");
const ProcessCollector = require("./collectors/process.collector");
const FilewatchCollector = require("./collectors/filewatch.collector");
const HeartbeatCollector = require("./collectors/heartbeat.collector");
const SystemCollector = require("./collectors/system.collector");
const WindowsEventCollector = require("./collectors/windows-event.collector");
const SpoolStore = require("./utils/spoolStore");

const splitList = (value = "") =>
  String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

const config = {
  apiUrl: normalizeApiRoot(process.env.THREATLENS_API_URL || "http://localhost:5000"),
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "",
  assetId: process.env.ASSET_ID || "agent-001",
  batchSize: Number(process.env.BATCH_SIZE || 5),
  flushIntervalMs: Number(process.env.FLUSH_INTERVAL_MS || 5000),
  maxRetries: Number(process.env.MAX_RETRIES || 3),
  systemIntervalMs: Number(process.env.SYSTEM_INTERVAL_MS || 15000),
  processIntervalMs: Number(process.env.PROCESS_INTERVAL_MS || 12000),
  windowsEventIntervalMs: Number(process.env.WINDOWS_EVENT_INTERVAL_MS || 10000),
  windowsEventEnabled:
    String(process.env.WINDOWS_EVENT_COLLECTION_ENABLED || "true").toLowerCase() === "true",
  heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS || 15000),
  maxBufferSize: Number(process.env.MAX_BUFFER_SIZE || 1000),
  fileWatchPaths: splitList(process.env.FILE_WATCH_PATHS || process.env.FILEWATCH_PATHS || ""),
  fileWatchEnabled: String(process.env.FILE_WATCH_ENABLED || "true").toLowerCase() === "true",
  spoolPath:
    process.env.SPOOL_FILE_PATH ||
    path.join(__dirname, "agent-data", "host-events-spool.jsonl"),
};

class ThreatLensHostAgent {
  constructor(runtimeConfig) {
    this.config = runtimeConfig;
    this.apiClient = new ThreatLensAPIClient(runtimeConfig);
    this.authCollector = new AuthCollector();
    this.processCollector = new ProcessCollector();
    this.systemCollector = new SystemCollector();
    this.heartbeatCollector = new HeartbeatCollector();
    this.windowsEventCollector = new WindowsEventCollector();
    this.filewatchCollector = new FilewatchCollector({
      paths: runtimeConfig.fileWatchPaths,
    });
    this.spoolStore = new SpoolStore(runtimeConfig.spoolPath);
    this.buffer = [];
    this.timers = [];
    this.flushing = false;
  }

  enqueue(event) {
    if (this.buffer.length >= this.config.maxBufferSize) {
      this.buffer.shift();
      logger.warn(`Host agent buffer limit reached. Dropping oldest event to stay within ${this.config.maxBufferSize}.`);
    }

    this.buffer.push(event);
    this.spoolStore.persist(this.buffer);
    logger.info(`Buffered event: ${event.eventType} (${this.buffer.length})`);

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
      logger.info(`Flushing ${batch.length} host event(s) to backend`);
      const result = await this.apiClient.submitLogs(batch);
      logger.info(
        `Submitted ${batch.length} host event(s). Inserted: ${result?.inserted ?? "n/a"}`
      );
      this.spoolStore.persist(this.buffer);
    } catch (error) {
      logger.error(
        `Host event submission failed: ${
          error.response
            ? `${error.response.status} ${JSON.stringify(error.response.data)}`
            : error.message
        }`
      );
      this.buffer.unshift(...batch);
      if (this.buffer.length > this.config.maxBufferSize) {
        this.buffer = this.buffer.slice(0, this.config.maxBufferSize);
      }
      this.spoolStore.persist(this.buffer);
    } finally {
      this.flushing = false;
    }
  }

  async sendHeartbeat() {
    const heartbeat = this.heartbeatCollector.collect({
      assetId: this.config.assetId,
      agentType: "hids",
      agentVersion: "1.1.0",
      telemetryTypes: [
        "host",
        "process",
        ...(this.config.windowsEventEnabled && process.platform === "win32"
          ? ["windows-eventlog"]
          : []),
        ...(this.config.fileWatchEnabled && this.config.fileWatchPaths.length > 0 ? ["filewatch"] : []),
      ],
      queueDepth: this.buffer.length,
    });

    try {
      await this.apiClient.sendHeartbeat(heartbeat);
      logger.info("Heartbeat sent");
    } catch (error) {
      logger.warn(
        `Heartbeat failed: ${
          error.response
            ? `${error.response.status} ${JSON.stringify(error.response.data)}`
            : error.message
        }`
      );
    }
  }

  startCollectors() {
    this.enqueue(
      this.authCollector.collect({
        message: "ThreatLens host agent started",
        eventType: "auth.login",
        loginSuccess: true,
        userName: process.env.USERNAME || process.env.USER || "unknown",
        metadata: {
          startup: true,
        },
      })
    );

    this.timers.push(
      setInterval(() => {
        this.enqueue(
          this.systemCollector.collect({
            message: "System telemetry heartbeat",
            metadata: {
              collectedBy: "system.collector",
            },
          })
        );
      }, this.config.systemIntervalMs)
    );

    this.timers.push(
      setInterval(() => {
        this.enqueue(
          this.processCollector.collect({
            message: `Process monitor tick: ${path.basename(process.argv[1] || "node")}`,
            processName: path.basename(process.argv[1] || "node"),
            commandLine: process.argv.join(" "),
            pid: process.pid,
            parentPid: process.ppid,
            userName: process.env.USERNAME || process.env.USER || "unknown",
            metadata: {
              collectedBy: "process.collector",
            },
          })
        );
      }, this.config.processIntervalMs)
    );

    if (this.config.windowsEventEnabled && process.platform === "win32") {
      this.timers.push(
        setInterval(async () => {
          const events = await this.windowsEventCollector.collect();
          events.forEach((event) => this.enqueue(event));
        }, this.config.windowsEventIntervalMs)
      );
      logger.info("Windows Event Log collector enabled");
    } else {
      logger.info("Windows Event Log collector disabled or unsupported on this platform");
    }

    this.timers.push(
      setInterval(() => {
        void this.sendHeartbeat();
      }, this.config.heartbeatIntervalMs)
    );

    this.timers.push(
      setInterval(() => {
        void this.flush();
      }, this.config.flushIntervalMs)
    );

    if (this.config.fileWatchEnabled && this.config.fileWatchPaths.length > 0) {
      const watchCount = this.filewatchCollector.start((event) => this.enqueue(event));
      logger.info(`Filewatch collector active on ${watchCount} path(s)`);
    } else {
      logger.info("Filewatch collector disabled or no paths configured");
    }
  }

  async start() {
    logger.info("ThreatLens Host Agent Starting");
    logger.info(`Backend URL: ${this.config.apiUrl}`);
    logger.info(`Asset ID: ${this.config.assetId}`);

    this.buffer = this.spoolStore.load();
    if (this.buffer.length > this.config.maxBufferSize) {
      this.buffer = this.buffer.slice(0, this.config.maxBufferSize);
      this.spoolStore.persist(this.buffer);
    }
    if (this.buffer.length > 0) {
      logger.info(`Recovered ${this.buffer.length} buffered event(s) from local spool`);
    }

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

    this.startCollectors();
    if (this.config.windowsEventEnabled && process.platform === "win32") {
      const startupWindowsEvents = await this.windowsEventCollector.collect();
      startupWindowsEvents.forEach((event) => this.enqueue(event));
    }
    await this.sendHeartbeat();
    await this.flush();

    process.on("SIGINT", async () => {
      logger.info("Stopping host agent");
      this.timers.forEach((timer) => clearInterval(timer));
      this.filewatchCollector.stop();
      await this.flush();
      process.exit(0);
    });

    logger.info("Host agent running");
  }
}

(async () => {
  try {
    const agent = new ThreatLensHostAgent(config);
    await agent.start();
  } catch (error) {
    logger.error(`Host agent crashed: ${error.message}`);
  }
})();
