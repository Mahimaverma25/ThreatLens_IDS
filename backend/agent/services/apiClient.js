const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const trimTrailingSlashes = (value = "") =>
  String(value).replace(/\/+$/, "");

const normalizeApiRoot = (value = "") =>
  trimTrailingSlashes(
    String(value || "http://localhost:5001").replace(/\/api\/?$/, "")
  );

const stableStringify = (body) => JSON.stringify(body || {});

const getPayloadHash = (body) =>
  crypto.createHash("sha256").update(stableStringify(body), "utf8").digest("hex");

const getSigningKey = (secret) =>
  crypto.createHash("sha256").update(String(secret || ""), "utf8").digest();

const buildSignature = ({ secret, timestamp, nonce, assetId, body }) =>
  crypto
    .createHmac("sha256", getSigningKey(secret))
    .update(`${timestamp}.${nonce}.${assetId}.${getPayloadHash(body)}`, "utf8")
    .digest("hex");

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class ThreatLensAPIClient {
  constructor(options = {}) {
    this.apiUrl = normalizeApiRoot(
      options.apiUrl || process.env.THREATLENS_API_URL || "http://localhost:5001"
    );

    this.apiKey = options.apiKey || process.env.THREATLENS_API_KEY || "";
    this.apiSecret = options.apiSecret || process.env.THREATLENS_API_SECRET || "";
    this.assetId = options.assetId || process.env.ASSET_ID || "";

    this.maxRetries = Number(options.maxRetries || process.env.MAX_RETRIES || 3);
    this.retryBaseDelayMs = Number(
      options.retryBaseDelayMs || process.env.RETRY_BASE_DELAY_MS || 1000
    );
    this.maxRetryDelayMs = Number(
      options.maxRetryDelayMs || process.env.MAX_RETRY_DELAY_MS || 15000
    );

    this.client = axios.create({
      baseURL: this.apiUrl,
      timeout: Number(process.env.API_TIMEOUT_MS || 10000),
      headers: {
        "User-Agent": `ThreatLens-Agent/${process.env.AGENT_VERSION || "1.0.0"}`,
      },
    });
  }

  validateCredentials() {
    return Boolean(this.apiKey && this.apiSecret && this.assetId);
  }

  buildHeaders(body) {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString("hex");

    const signature = buildSignature({
      secret: this.apiSecret,
      timestamp,
      nonce,
      assetId: this.assetId,
      body,
    });

    return {
      "Content-Type": "application/json",

      // Keep lowercase because Node/Express normalizes headers anyway.
      "x-api-key": this.apiKey,
      "x-timestamp": timestamp,
      "x-nonce": nonce,
      "x-asset-id": this.assetId,
      "x-signature": signature,
      "x-signature-version": "v2",
    };
  }

  getRetryDelay(attempt) {
    const exponential = this.retryBaseDelayMs * 2 ** Math.max(attempt - 1, 0);
    const jitter = Math.floor(Math.random() * Math.max(250, this.retryBaseDelayMs));
    return Math.min(this.maxRetryDelayMs, exponential + jitter);
  }

  shouldRetry(error, attempt) {
    const status = Number(error.response?.status || 0);

    if (attempt >= this.maxRetries) return false;

    // Do not retry auth/signature/conflict problems.
    if ([400, 401, 403, 409].includes(status)) return false;

    // Retry rate limit and server/network errors.
    if (status === 429 || status >= 500 || !status) return true;

    return false;
  }

  formatError(error, action) {
    const status = error.response?.status;
    const data = error.response?.data;

    const serverMessage =
      data?.message || data?.error || error.message || "Unknown error";

    return new Error(
      `${action} failed${status ? ` with status ${status}` : ""}: ${serverMessage}`
    );
  }

  async submitLogs(logs, attempt = 1) {
    if (!this.validateCredentials()) {
      throw new Error(
        "Missing THREATLENS_API_KEY, THREATLENS_API_SECRET, or ASSET_ID"
      );
    }

    const payload = Array.isArray(logs?.logs)
      ? logs
      : { logs: Array.isArray(logs) ? logs : [logs] };

    try {
      const response = await this.client.post("/api/logs/ingest", payload, {
        headers: this.buildHeaders(payload),
      });

      return response.data;
    } catch (error) {
      if (!this.shouldRetry(error, attempt)) {
        throw this.formatError(error, "Log submission");
      }

      await wait(this.getRetryDelay(attempt));
      return this.submitLogs(payload.logs, attempt + 1);
    }
  }

  async sendHeartbeat(payload = {}, attempt = 1) {
    if (!this.validateCredentials()) {
      throw new Error(
        "Missing THREATLENS_API_KEY, THREATLENS_API_SECRET, or ASSET_ID"
      );
    }

    const heartbeatPayload = {
      asset_id: this.assetId,
      agent_version: process.env.AGENT_VERSION || "1.0.0",
      agent_mode: process.env.AGENT_MODE || "host",
      timestamp: new Date().toISOString(),
      ...payload,
    };

    try {
      const response = await this.client.post(
        "/api/agents/heartbeat",
        heartbeatPayload,
        {
          headers: this.buildHeaders(heartbeatPayload),
        }
      );

      return response.data;
    } catch (error) {
      if (!this.shouldRetry(error, attempt)) {
        throw this.formatError(error, "Heartbeat");
      }

      await wait(this.getRetryDelay(attempt));
      return this.sendHeartbeat(heartbeatPayload, attempt + 1);
    }
  }

  async healthCheck() {
    try {
      const response = await this.client.get("/health");
      return response.data;
    } catch (error) {
      throw this.formatError(error, "Health check");
    }
  }
}

module.exports = {
  ThreatLensAPIClient,
  normalizeApiRoot,
  buildSignature,
};