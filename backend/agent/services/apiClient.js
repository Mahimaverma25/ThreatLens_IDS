const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const trimTrailingSlashes = (value = "") => String(value).replace(/\/+$/, "");
const normalizeApiRoot = (value = "") =>
  trimTrailingSlashes(
    String(value || "http://localhost:5001").replace(/\/api\/?$/, "")
  );
const getPayloadHash = (body) =>
  crypto.createHash("sha256").update(JSON.stringify(body), "utf8").digest("hex");
const getSigningKey = (secret) =>
  crypto.createHash("sha256").update(String(secret || ""), "utf8").digest("hex");
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
      timeout: 10000,
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
      "x-api-key": this.apiKey,
      "x-timestamp": timestamp,
      "x-signature": signature,
      "x-signature-version": "v2",
      "x-nonce": nonce,
      "x-asset-id": this.assetId,
    };
  }

  getRetryDelay(attempt) {
    const exponential = this.retryBaseDelayMs * 2 ** Math.max(attempt - 1, 0);
    const jitter = Math.floor(Math.random() * Math.max(250, this.retryBaseDelayMs));
    return Math.min(this.maxRetryDelayMs, exponential + jitter);
  }

  async submitLogs(logs, attempt = 1) {
    if (!this.validateCredentials()) {
      throw new Error("Missing THREATLENS_API_KEY, THREATLENS_API_SECRET, or ASSET_ID");
    }

    const payload = Array.isArray(logs?.logs) ? logs : { logs };

    try {
      const response = await this.client.post("/api/logs/ingest", payload, {
        headers: this.buildHeaders(payload),
      });
      return response.data;
    } catch (error) {
      if (
        attempt >= this.maxRetries ||
        [401, 409].includes(Number(error.response?.status || 0))
      ) {
        throw error;
      }

      await wait(this.getRetryDelay(attempt));
      return this.submitLogs(payload.logs, attempt + 1);
    }
  }

  async sendHeartbeat(payload, attempt = 1) {
    if (!this.validateCredentials()) {
      throw new Error("Missing THREATLENS_API_KEY, THREATLENS_API_SECRET, or ASSET_ID");
    }

    try {
      const response = await this.client.post("/api/agents/heartbeat", payload, {
        headers: this.buildHeaders(payload),
      });
      return response.data;
    } catch (error) {
      if (
        attempt >= this.maxRetries ||
        [401, 409].includes(Number(error.response?.status || 0))
      ) {
        throw error;
      }

      await wait(this.getRetryDelay(attempt));
      return this.sendHeartbeat(payload, attempt + 1);
    }
  }

  async healthCheck() {
    const response = await this.client.get("/health");
    return response.data;
  }
}

module.exports = {
  ThreatLensAPIClient,
  normalizeApiRoot,
};
