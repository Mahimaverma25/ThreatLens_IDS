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

let SnortCollector = null;
try {
  SnortCollector = require("./collectors/snort.collector");
} catch (_) {
  SnortCollector = null;
}

const splitList = (value = "") =>
  String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

const config = {
  idsEngineUrl: process.env.IDS_ENGINE_URL || "http://localhost:8000/api/detect",
  idsBatchUrl: process.env.IDS_BATCH_URL || "http://localhost:8000/api/detect/batch",

  apiUrl: normalizeApiRoot(process.env.THREATLENS_API_URL || "http://localhost:5001"),
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "",

  agentId: process.env.AGENT_ID || "agent-001",
  assetId: process.env.ASSET_ID || "host-001",

  batchSize: Number(process.env.BATCH_SIZE || 10),
  flushIntervalMs: Number(process.env.FLUSH_INTERVAL || process.env.FLUSH_INTERVAL_MS || 5000),
  maxRetries: Number(process.env.MAX_RETRIES || 3),

  systemIntervalMs: Number(process.env.SYSTEM_INTERVAL_MS || 15000),
  processIntervalMs: Number(process.env.PROCESS_INTERVAL_MS || 12000),
  windowsEventIntervalMs: Number(process.env.WINDOWS_EVENT_INTERVAL_MS || 10000),
  heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS || 15000),

  maxBufferSize: Number(process.env.MAX_BUFFER_SIZE || 1000),

  windowsEventEnabled:
    String(process.env.WINDOWS_EVENT_COLLECTION_ENABLED || "true").toLowerCase() === "true",

  fileWatchEnabled:
    String(process.env.ENABLE_FILE_WATCH || process.env.FILE_WATCH_ENABLED || "true").toLowerCase() === "true",

  fileWatchPaths: splitList(process.env.FILE_WATCH_PATHS || process.env.FILEWATCH_PATHS || ""),

  enableSnort:
    String(process.env.ENABLE_SNORT || "false").toLowerCase() === "true",

  snortLogPath:
    process.env.SNORT_LOG_PATH || "/var/log/snort/alert_fast.txt",

  spoolPath:
    process.env.SPOOL_FILE_PATH ||
    path.join(__dirname, "agent-data", "host-events-spool.jsonl"),
};

function normalizeForIdsEngine(event = {}) {
  const metadata = event.metadata || {};

  return {
    event_id: event.eventId || event.event_id || `${config.agentId}-${Date.now()}`,
    timestamp: event.timestamp || new Date().toISOString(),

    source: event.source || "threatlens-agent",
    event_type: event.eventType || event.event_type || "host_event",

    agent_id: config.agentId,
    asset_id: config.assetId,

    src_ip: event.src_ip || event.source_ip || metadata.src_ip || "127.0.0.1",
    dest_ip: event.dest_ip || event.destination_ip || metadata.dest_ip || "127.0.0.1",

    src_port: Number(event.src_port || metadata.src_port || 0),
    dest_port: Number(event.dest_port || event.destination_port || event.port || metadata.dest_port || 0),
    port: Number(event.dest_port || event.destination_port || event.port || metadata.dest_port || 0),

    protocol: String(event.protocol || metadata.protocol || "TCP").toUpperCase(),

    packets: Number(event.packets || metadata.packets || 1),
    bytes: Number(event.bytes || metadata.bytes || 0),
    duration: Number(event.duration || metadata.duration || 0),

    request_rate: Number(event.request_rate || metadata.request_rate || 0),
    failed_attempts: Number(event.failed_attempts || event.failedAttempts || metadata.failed_attempts || 0),
    flow_count: Number(event.flow_count || event.flowCount || metadata.flow_count || 1),
    unique_ports: Number(event.unique_ports || event.uniquePorts || metadata.unique_ports || 1),
    dns_queries: Number(event.dns_queries || event.dnsQueries || metadata.dns_queries || 0),
    smb_writes: Number(event.smb_writes || event.smbWrites || metadata.smb_writes || 0),

    snort_priority: Number(event.snort_priority || event.priority || 0),
    is_snort: Number(event.is_snort || 0),

    attack_type: event.attack_type || event.type || event.message || "host_telemetry",
    message: event.message || "ThreatLens agent event",

    raw: event,
  };
}

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
    this.snortWatcher = null;
  }

  enqueue(event) {
    const normalized = normalizeForIdsEngine(event);

    if (this.buffer.length >= this.config.maxBufferSize) {
      this.buffer.shift();
      logger.warn(`Buffer limit reached. Dropping oldest event.`);
    }

    this.buffer.push(normalized);
    this.spoolStore.persist(this.buffer);

    logger.info(`Buffered event: ${normalized.event_type} (${this.buffer.length})`);

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
      logger.info(`Sending ${batch.length} event(s) to IDS engine`);

      const result = await this.apiClient.detectBatch(batch);

      logger.info(
        `IDS engine accepted ${batch.length} event(s). Status: ${result?.status || "ok"}`
      );

      this.spoolStore.persist(this.buffer);
    } catch (error) {
      logger.error(
        `IDS engine submission failed: ${
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
      agentType: this.config.enableSnort ? "hybrid" : "hids",
      agentVersion: "2.0.0",
      telemetryTypes: [
        "host",
        "process",
        "system",
        ...(this.config.enableSnort ? ["snort", "nids"] : []),
        ...(this.config.windowsEventEnabled && process.platform === "win32"
          ? ["windows-eventlog"]
          : []),
        ...(this.config.fileWatchEnabled && this.config.fileWatchPaths.length > 0
          ? ["filewatch"]
          : []),
      ],
      queueDepth: this.buffer.length,
    });

    try {
      if (typeof this.apiClient.sendHeartbeat === "function") {
        await this.apiClient.sendHeartbeat(heartbeat);
      }
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
        message: "ThreatLens agent started",
        eventType: "agent.startup",
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
      logger.info("Windows Event Log collector disabled or unsupported");
    }

    if (this.config.fileWatchEnabled && this.config.fileWatchPaths.length > 0) {
      const watchCount = this.filewatchCollector.start((event) => this.enqueue(event));
      logger.info(`Filewatch collector active on ${watchCount} path(s)`);
    } else {
      logger.info("Filewatch collector disabled or no paths configured");
    }

    if (this.config.enableSnort && SnortCollector?.startSnortCollector) {
      this.snortWatcher = SnortCollector.startSnortCollector(
        (event) => this.enqueue(event),
        {
          filePath: this.config.snortLogPath,
          readExisting: false,
        }
      );

      if (this.snortWatcher) {
        logger.info("Snort collector enabled");
      }
    } else {
      logger.info("Snort collector disabled or collector file missing");
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
  }

  async start() {
    logger.info("ThreatLens Hybrid Agent Starting");
    logger.info(`IDS Engine Detect URL: ${this.config.idsEngineUrl}`);
    logger.info(`IDS Engine Batch URL: ${this.config.idsBatchUrl}`);
    logger.info(`Asset ID: ${this.config.assetId}`);

    this.buffer = this.spoolStore.load();

    if (this.buffer.length > this.config.maxBufferSize) {
      this.buffer = this.buffer.slice(0, this.config.maxBufferSize);
      this.spoolStore.persist(this.buffer);
    }

    if (this.buffer.length > 0) {
      logger.info(`Recovered ${this.buffer.length} buffered event(s) from spool`);
    }

    try {
      await this.apiClient.healthCheck();
      logger.info("IDS engine connected");
    } catch (error) {
      logger.warn(
        `IDS engine health check failed: ${
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
      logger.info("Stopping ThreatLens agent");

      this.timers.forEach((timer) => clearInterval(timer));

      if (this.filewatchCollector?.stop) {
        this.filewatchCollector.stop();
      }

      if (this.snortWatcher?.stop) {
        this.snortWatcher.stop();
      }

      await this.flush();

      process.exit(0);
    });

    logger.info("ThreatLens Hybrid Agent running");
  }
}

(async () => {
  try {
    const agent = new ThreatLensHostAgent(config);
    await agent.start();
  } catch (error) {
    logger.error(`ThreatLens agent crashed: ${error.message}`);
    process.exit(1);
  }
})();