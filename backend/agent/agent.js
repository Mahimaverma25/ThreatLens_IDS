require("dotenv").config();

const fs = require("fs");
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
  String(value).split(",").map((x) => x.trim()).filter(Boolean);

const config = {
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

  enableSnort: String(process.env.ENABLE_SNORT || "false").toLowerCase() === "true",
  snortLogPath: process.env.SNORT_LOG_PATH || "/var/log/snort/alert_fast.txt",

  spoolPath:
    process.env.SPOOL_FILE_PATH ||
    path.join(__dirname, "agent-data", "host-events-spool.jsonl"),

  clearSpoolOnStart:
    String(process.env.CLEAR_SPOOL_ON_START || "false").toLowerCase() === "true",
};

const makeEventId = () =>
  `${config.agentId}-${Date.now()}-${Math.random().toString(16).slice(2)}`;

function normalizeForBackend(event = {}) {
  const metadata =
    event.metadata && typeof event.metadata === "object" ? { ...event.metadata } : {};

  return {
    eventId: event.eventId || event.event_id || metadata.uuid || makeEventId(),
    timestamp: event.timestamp || new Date().toISOString(),
    source: event.source || "threatlens-agent",
    eventType: event.eventType || event.event_type || "host_event",
    ip:
      event.ip ||
      event.src_ip ||
      event.source_ip ||
      metadata.sourceIp ||
      metadata.src_ip ||
      "127.0.0.1",
    message: event.message || "ThreatLens agent event",
    assetId: event.assetId || event.asset_id || config.assetId,
    metadata: {
      ...metadata,
      agentId: metadata.agentId || config.agentId,
      assetId: metadata.assetId || event.assetId || event.asset_id || config.assetId,
      sourceIp: metadata.sourceIp || event.src_ip || event.source_ip || metadata.src_ip,
      destinationIp:
        metadata.destinationIp || event.dest_ip || event.destination_ip || metadata.dest_ip,
      sourcePort: metadata.sourcePort ?? event.src_port ?? metadata.src_port,
      destinationPort:
        metadata.destinationPort ??
        event.dest_port ??
        event.destination_port ??
        event.port ??
        metadata.dest_port,
      port:
        metadata.port ??
        event.dest_port ??
        event.destination_port ??
        event.port ??
        metadata.dest_port,
      protocol: metadata.protocol || event.protocol,
      packets: metadata.packets ?? event.packets,
      bytes: metadata.bytes ?? event.bytes,
      duration: metadata.duration ?? event.duration,
      requestRate:
        metadata.requestRate ?? event.request_rate ?? event.requestRate ?? metadata.request_rate,
      failedAttempts:
        metadata.failedAttempts ??
        event.failed_attempts ??
        event.failedAttempts ??
        metadata.failed_attempts,
      flowCount: metadata.flowCount ?? event.flow_count ?? event.flowCount ?? metadata.flow_count,
      uniquePorts:
        metadata.uniquePorts ??
        event.unique_ports ??
        event.uniquePorts ??
        metadata.unique_ports,
      dnsQueries:
        metadata.dnsQueries ?? event.dns_queries ?? event.dnsQueries ?? metadata.dns_queries,
      smbWrites: metadata.smbWrites ?? event.smb_writes ?? event.smbWrites ?? metadata.smb_writes,
      snort: metadata.snort,
      legacyRaw: event.raw,
    },
  };
}

function restoreBufferedEvent(entry = {}) {
  if (entry?.eventType || entry?.metadata) return normalizeForBackend(entry);
  if (entry?.raw && typeof entry.raw === "object") return normalizeForBackend(entry.raw);
  return normalizeForBackend(entry);
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
    const normalized = normalizeForBackend(event);

    if (this.buffer.length >= this.config.maxBufferSize) {
      this.buffer.shift();
      logger.warn("Buffer limit reached. Dropping oldest event.");
    }

    this.buffer.push(normalized);
    this.spoolStore.persist(this.buffer);

    logger.info(`Buffered event: ${normalized.eventType} (${this.buffer.length})`);

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
      logger.info(`Sending ${batch.length} event(s) to ThreatLens backend`);

      const result = await this.apiClient.submitLogs(batch);

      logger.info(
        `ThreatLens backend accepted ${batch.length} event(s). Inserted: ${
          result?.inserted ?? result?.insertedCount ?? result?.count ?? "n/a"
        }`
      );

      this.spoolStore.persist(this.buffer);
    } catch (error) {
      logger.error(
        `ThreatLens backend submission failed: ${
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
        message: "ThreatLens agent started",
        eventType: "agent.startup",
        loginSuccess: true,
        userName: process.env.USERNAME || process.env.USER || "unknown",
        metadata: { startup: true },
      })
    );

    this.timers.push(
      setInterval(() => {
        this.enqueue(
          this.systemCollector.collect({
            message: "System telemetry heartbeat",
            metadata: { collectedBy: "system.collector" },
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
            metadata: { collectedBy: "process.collector" },
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

      if (this.snortWatcher) logger.info("Snort collector enabled");
    } else {
      logger.info("Snort collector disabled or collector file missing");
    }

    this.timers.push(setInterval(() => void this.sendHeartbeat(), this.config.heartbeatIntervalMs));
    this.timers.push(setInterval(() => void this.flush(), this.config.flushIntervalMs));
  }

  async start() {
    logger.info("ThreatLens Hybrid Agent Starting");
    logger.info(`ThreatLens API URL: ${this.config.apiUrl}`);
    logger.info(`Asset ID: ${this.config.assetId}`);

    if (this.config.clearSpoolOnStart && fs.existsSync(this.config.spoolPath)) {
      fs.unlinkSync(this.config.spoolPath);
      logger.warn("Old spool file cleared because CLEAR_SPOOL_ON_START=true");
    }

    this.buffer = this.spoolStore.load().map(restoreBufferedEvent);

    if (this.buffer.length > this.config.maxBufferSize) {
      this.buffer = this.buffer.slice(0, this.config.maxBufferSize);
      this.spoolStore.persist(this.buffer);
    }

    if (this.buffer.length > 0) {
      logger.info(`Recovered ${this.buffer.length} buffered event(s) from spool`);
    }

    try {
      await this.apiClient.healthCheck();
      logger.info("ThreatLens backend connected");
    } catch (error) {
      logger.warn(
        `ThreatLens backend health check failed: ${
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

      if (this.filewatchCollector?.stop) this.filewatchCollector.stop();
      if (this.snortWatcher?.stop) this.snortWatcher.stop();

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