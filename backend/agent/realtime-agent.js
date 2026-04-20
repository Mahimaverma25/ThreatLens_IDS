require("dotenv").config();

const axios = require("axios");
const fs = require("fs");
const { spawnSync } = require("child_process");
const { Tail } = require("tail");
const winston = require("winston");

const { SIGNATURE_VERSION, buildSignature } = require("./ingest-signature");
const { parseFastAlertLine, parseEveJsonLine } = require("./snort-parsers");
const packageJson = require("./package.json");

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(
      ({ timestamp, level, message }) =>
        `${timestamp} [${level.toUpperCase()}] ${message}`
    )
  ),
  transports: [new winston.transports.Console()],
});

const splitList = (value) =>
  String(value || "")
    .split(",")
    .map((item) =>
      item
        .replace(/\r/g, "")
        .replace(/\n/g, "")
        .trim()
        .replace(/^['"]|['"]$/g, "")
    )
    .filter(Boolean);

const unique = (values) => [...new Set(values.filter(Boolean))];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let cachedWslDistroName = null;

const getWslDistroName = () => {
  if (cachedWslDistroName !== null) {
    return cachedWslDistroName;
  }

  const envDistro = String(process.env.WSL_DISTRO_NAME || "").trim();
  if (envDistro) {
    cachedWslDistroName = envDistro;
    return cachedWslDistroName;
  }

  if (process.platform !== "win32") {
    cachedWslDistroName = "";
    return cachedWslDistroName;
  }

  try {
    const result = spawnSync("wsl.exe", ["bash", "-lc", "printf %s \"$WSL_DISTRO_NAME\""], {
      encoding: "utf8",
      timeout: 5000,
      windowsHide: true,
    });

    cachedWslDistroName = String(result.stdout || "").trim();
    return cachedWslDistroName;
  } catch (error) {
    cachedWslDistroName = "";
    return cachedWslDistroName;
  }
};

const translateWslLinuxPathForWindowsNode = (filePath) => {
  const normalized = String(filePath || "")
    .replace(/\r/g, "")
    .replace(/\n/g, "")
    .trim();

  if (!normalized) {
    return "";
  }

  const distroName = getWslDistroName();
  const looksLikeLinuxAbsolutePath = normalized.startsWith("/");

  if (process.platform !== "win32" || !distroName || !looksLikeLinuxAbsolutePath) {
    return normalized;
  }

  const windowsPath = normalized.split("/").filter(Boolean).join("\\");
  return `\\\\wsl$\\${distroName}\\${windowsPath}`;
};

const DEFAULT_WINDOWS_SNORT_PATHS = {
  fast: [
    "C:\\snort\\log\\alert_fast.txt",
    "C:\\Snort\\log\\alert_fast.txt",
    "C:\\snort\\log\\alert",
    "C:\\Snort\\log\\alert",
  ],
  json: ["C:\\snort\\log\\eve.json", "C:\\Snort\\log\\eve.json"],
};

const normalizeApiUrl = (value) => {
  const raw = String(value || "http://localhost:5000").trim().replace(/\/+$/, "");
  return raw.endsWith("/api") ? raw : `${raw}/api`;
};

const resolveSnortPaths = (configuredPaths, fallbackPaths) => {
  const explicitPaths = unique(
    configuredPaths
      .filter(Boolean)
      .map((filePath) => translateWslLinuxPathForWindowsNode(filePath))
  );
  const discoveredFallbacks = unique(
    fallbackPaths
      .map((filePath) =>
        translateWslLinuxPathForWindowsNode(
          String(filePath || "")
            .replace(/\r/g, "")
            .replace(/\n/g, "")
            .trim()
        )
      )
      .filter((filePath) => filePath && fs.existsSync(filePath))
  );
  return unique([...explicitPaths, ...discoveredFallbacks]);
};

const describeError = (error) => {
  if (!error) {
    return "Unknown error";
  }

  if (error.response) {
    return `${error.response.status} ${JSON.stringify(error.response.data || {})}`;
  }

  if (error.code && error.message) {
    return `${error.code}: ${error.message}`;
  }

  return error.message || String(error);
};

const inspectFileAccess = (filePath) => {
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
    return { exists: true, readable: true, reason: null };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { exists: false, readable: false, reason: "file does not exist" };
    }

    if (error.code === "EACCES" || error.code === "EPERM") {
      return {
        exists: true,
        readable: false,
        reason: "permission denied",
      };
    }

    return {
      exists: fs.existsSync(filePath),
      readable: false,
      reason: describeError(error),
    };
  }
};

const config = {
  apiUrl: normalizeApiUrl(process.env.THREATLENS_API_URL || "http://localhost:5000"),
  apiKey: process.env.THREATLENS_API_KEY || "",
  apiSecret: process.env.THREATLENS_API_SECRET || "",
  assetId: process.env.ASSET_ID || "agent-001",
  agentMode: (process.env.AGENT_MODE || "snort").trim().toLowerCase(),
  batchSize: Number.parseInt(process.env.BATCH_SIZE || "20", 10),
  batchTimeoutMs: Number.parseInt(process.env.BATCH_TIMEOUT_MS || "5000", 10),
  healthCheckIntervalMs: Number.parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || "60000", 10),
  fileDiscoveryIntervalMs: Number.parseInt(process.env.FILE_DISCOVERY_INTERVAL_MS || "10000", 10),
  bootstrapMaxLines: Number.parseInt(process.env.BOOTSTRAP_MAX_LINES || "500", 10),
  maxBufferSize: Number.parseInt(process.env.MAX_BUFFER_SIZE || "5000", 10),
  maxRetries: Number.parseInt(process.env.MAX_RETRIES || "3", 10),
  retryDelayMs: Number.parseInt(process.env.RETRY_DELAY_MS || "1500", 10),
  snortFastLogPaths: resolveSnortPaths(
    splitList(
      process.env.SNORT_FAST_LOG_PATHS ||
        process.env.SNORT_FAST_LOG_PATH ||
        process.env.SNORT_ALERT_FILE ||
        ""
    ),
    DEFAULT_WINDOWS_SNORT_PATHS.fast
  ),
  snortJsonLogPaths: resolveSnortPaths(
    splitList(process.env.SNORT_EVE_JSON_PATHS || process.env.SNORT_EVE_JSON_PATH || ""),
    DEFAULT_WINDOWS_SNORT_PATHS.json
  ),
};

class APIClient {
  constructor(runtimeConfig) {
    this.apiKey = runtimeConfig.apiKey;
    this.apiSecret = runtimeConfig.apiSecret;
    this.assetId = runtimeConfig.assetId;
    this.maxRetries = runtimeConfig.maxRetries;
    this.retryDelayMs = runtimeConfig.retryDelayMs;
    this.apiUrl = runtimeConfig.apiUrl;
    this.healthUrl = this.apiUrl.replace(/\/api$/, "");
    this.client = axios.create({
      baseURL: this.apiUrl,
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
      const timestamp = Date.now().toString();
      const signature = buildSignature({
        apiSecret: this.apiSecret,
        timestamp,
        assetId: this.assetId,
        body: payload,
      });

      logger.info(`Sending ${logs.length} Snort log(s) to ThreatLens (attempt ${attempt})`);

      const response = await this.client.post("/logs/ingest", payload, {
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.apiKey,
          "x-timestamp": timestamp,
          "x-signature": signature,
          "x-signature-version": SIGNATURE_VERSION,
          "x-asset-id": this.assetId,
          "x-agent-version": packageJson.version,
        },
      });

      logger.info(
        `Submit success: ${response.status} inserted=${response.data?.inserted ?? 0} duplicates=${response.data?.duplicates ?? 0}`
      );
      return true;
    } catch (error) {
      if (error.response) {
        logger.error(`${error.response.status}: ${JSON.stringify(error.response.data)}`);

        if (error.response.status === 401) {
          logger.error("Unauthorized ingest request. Refresh backend and agent credentials.");
          return false;
        }
      } else {
        logger.error(`Network error: ${error.message}`);
      }

      if (attempt < this.maxRetries) {
        logger.warn(`Retrying submit (${attempt + 1}/${this.maxRetries})`);
        await sleep(this.retryDelayMs * attempt);
        return this.submitLogs(logs, attempt + 1);
      }

      logger.error("Submit failed after max retries");
      return false;
    }
  }

  async healthCheck() {
    try {
      await axios.get(`${this.healthUrl}/health`, { timeout: 3000 });
      return true;
    } catch (error) {
      logger.warn(`Backend health check failed: ${describeError(error)}`);
      return false;
    }
  }
}

class SnortLogCollector {
  constructor(runtimeConfig, onEvent) {
    this.onEvent = onEvent;
    this.watchers = new Map();
    this.missingFiles = new Set();
    this.bootstrappedFiles = new Set();
    this.fastLogPaths = runtimeConfig.snortFastLogPaths;
    this.jsonLogPaths = runtimeConfig.snortJsonLogPaths;
    this.fileDiscoveryIntervalMs = runtimeConfig.fileDiscoveryIntervalMs;
    this.bootstrapMaxLines = runtimeConfig.bootstrapMaxLines;
    this.discoveryTimer = null;
  }

  bootstrapFile(filePath, parser, label) {
    if (this.bootstrappedFiles.has(filePath)) {
      return;
    }

    try {
      const content = fs.readFileSync(filePath, "utf8");
      const lines = content
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);

      const bootstrapLines =
        this.bootstrapMaxLines > 0 ? lines.slice(-this.bootstrapMaxLines) : lines;

      let importedCount = 0;
      bootstrapLines.forEach((line) => {
        const parsed = parser(line);
        if (parsed) {
          this.onEvent(parsed);
          importedCount += 1;
        }
      });

      this.bootstrappedFiles.add(filePath);
      logger.info(
        `Bootstrapped ${importedCount} existing ${label} event(s) from ${filePath}`
      );
    } catch (error) {
      logger.error(`Failed to bootstrap ${label} file ${filePath}: ${error.message}`);
    }
  }

  watchFile(filePath, parser, label) {
    if (this.watchers.has(filePath)) {
      return;
    }

    const access = inspectFileAccess(filePath);

    if (!access.exists) {
      if (!this.missingFiles.has(filePath)) {
        logger.warn(`${label} file not found: ${filePath}`);
        this.missingFiles.add(filePath);
      }
      return;
    }

    if (!access.readable) {
      if (!this.missingFiles.has(filePath)) {
        logger.warn(
          `${label} file is not readable: ${filePath} (${access.reason}). ` +
            "If Snort runs under another user/group, grant read access or run the agent with permission to read the file."
        );
        this.missingFiles.add(filePath);
      }
      return;
    }

    this.missingFiles.delete(filePath);
    this.bootstrapFile(filePath, parser, label);

    const watcher = new Tail(filePath, {
      fromBeginning: false,
      fsWatchOptions: { interval: 1000 },
      useWatchFile: true,
    });

    watcher.on("line", (line) => {
      const parsed = parser(line);
      if (parsed) {
        this.onEvent(parsed);
      }
    });

    watcher.on("error", (error) => {
      logger.error(`Tail error for ${filePath}: ${error.message}`);
      this.watchers.delete(filePath);
    });

    this.watchers.set(filePath, watcher);
    logger.info(`Watching ${label} file: ${filePath}`);
  }

  attachConfiguredFiles() {
    this.fastLogPaths.forEach((filePath) => {
      this.watchFile(filePath, parseFastAlertLine, "Snort fast alert");
    });

    this.jsonLogPaths.forEach((filePath) => {
      this.watchFile(filePath, parseEveJsonLine, "Snort EVE JSON");
    });
  }

  start() {
    logger.info(
      `Configured Snort fast alert paths: ${
        this.fastLogPaths.length > 0 ? this.fastLogPaths.join(", ") : "(none)"
      }`
    );
    logger.info(`Agent runtime platform: ${process.platform}`);
    const distroName = getWslDistroName();
    if (process.platform === "win32" && distroName) {
      logger.info(
        `Agent is running with Windows Node inside WSL distro "${distroName}". Linux Snort paths will be translated to \\\\wsl$ shares automatically.`
      );
    }
    logger.info(
      `Configured Snort EVE JSON paths: ${
        this.jsonLogPaths.length > 0 ? this.jsonLogPaths.join(", ") : "(none)"
      }`
    );
    this.attachConfiguredFiles();

    if (this.watchers.size === 0) {
      logger.warn(
        "No readable Snort log files found. Set SNORT_FAST_LOG_PATH or SNORT_EVE_JSON_PATH to the real Snort output file and ensure the agent user can read it."
      );
    }

    this.discoveryTimer = setInterval(() => {
      this.attachConfiguredFiles();
    }, this.fileDiscoveryIntervalMs);
  }

  stop() {
    if (this.discoveryTimer) {
      clearInterval(this.discoveryTimer);
      this.discoveryTimer = null;
    }

    this.watchers.forEach((watcher) => watcher.unwatch());
    this.watchers.clear();
    this.missingFiles.clear();
  }
}

class ThreatLensAgent {
  constructor(runtimeConfig) {
    this.apiClient = new APIClient(runtimeConfig);
    this.mode = runtimeConfig.agentMode;
    this.batchSize = runtimeConfig.batchSize;
    this.batchTimeoutMs = runtimeConfig.batchTimeoutMs;
    this.healthCheckIntervalMs = runtimeConfig.healthCheckIntervalMs;
    this.maxBufferSize = runtimeConfig.maxBufferSize;
    this.buffer = [];
    this.flushTimer = null;
    this.flushInProgress = false;
    this.healthTimer = null;
    this.collector = new SnortLogCollector(runtimeConfig, (event) => this.enqueueEvent(event));
  }

  enqueueEvent(event) {
    if (this.buffer.length >= this.maxBufferSize) {
      const dropped = this.buffer.splice(0, this.buffer.length - this.maxBufferSize + 1);
      logger.warn(`Buffer full. Dropped ${dropped.length} oldest event(s).`);
    }

    this.buffer.push(event);
    logger.info(`Snort event buffered: ${event.message} (buffer: ${this.buffer.length})`);
    this.scheduleFlush();

    if (this.buffer.length >= this.batchSize) {
      void this.flushBuffer();
    }
  }

  async flushBuffer() {
    if (this.flushInProgress || this.buffer.length === 0) {
      return;
    }

    this.flushInProgress = true;

    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    const logsToSend = [...this.buffer];
    this.buffer = [];

    try {
      const success = await this.apiClient.submitLogs(logsToSend);
      if (!success) {
        logger.warn("Restoring failed batch to buffer");
        this.buffer = [...logsToSend, ...this.buffer].slice(0, this.maxBufferSize);
      }
    } finally {
      this.flushInProgress = false;

      if (this.buffer.length > 0) {
        this.scheduleFlush();
      }
    }
  }

  scheduleFlush() {
    if (this.flushTimer || this.flushInProgress) {
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
