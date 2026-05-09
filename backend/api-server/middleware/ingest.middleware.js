const crypto = require("crypto");

const APIKey = require("../models/APIKey");
const Asset = require("../models/Asset");
const config = require("../config/env");
const { reserveNonce } = require("../services/ingestNonce.service");
const { appLogger, serializeError } = require("../utils/logger");

const SIGNATURE_VERSION = "v2";

const buildPayloadHash = (body) =>
  crypto
    .createHash("sha256")
    .update(JSON.stringify(body || {}), "utf8")
    .digest("hex");

const getSigningKeyFromStoredHash = (secretHash) => {
  const value = String(secretHash || "").trim();

  // Compatible with agent apiClient.js:
  // agent uses crypto.createHash("sha256").update(secret).digest()
  if (/^[a-f0-9]{64}$/i.test(value)) {
    return Buffer.from(value, "hex");
  }

  return value;
};

const buildSignature = ({ signingKey, timestamp, nonce, assetId, body }) =>
  crypto
    .createHmac("sha256", signingKey)
    .update(`${timestamp}.${nonce}.${assetId}.${buildPayloadHash(body)}`, "utf8")
    .digest("hex");

const safeCompare = (provided, expected) => {
  try {
    if (!provided || !expected) return false;

    const providedBuffer = Buffer.from(String(provided), "hex");
    const expectedBuffer = Buffer.from(String(expected), "hex");

    if (providedBuffer.length !== expectedBuffer.length) return false;

    return crypto.timingSafeEqual(providedBuffer, expectedBuffer);
  } catch {
    return false;
  }
};

const getHeader = (req, name) => {
  const value = req.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
};

const validateAPIKey = async (req, res, next) => {
  try {
    const token = String(getHeader(req, "x-api-key") || "").trim();
    const timestamp = String(getHeader(req, "x-timestamp") || "").trim();
    const nonce = String(getHeader(req, "x-nonce") || "").trim();
    const assetIdHeader = String(getHeader(req, "x-asset-id") || "").trim();
    const signature = String(getHeader(req, "x-signature") || "").trim();
    const signatureVersion = String(
      getHeader(req, "x-signature-version") || SIGNATURE_VERSION
    ).trim();

    if (!token || !timestamp || !nonce || !assetIdHeader || !signature) {
      return res.status(401).json({
        success: false,
        error: "Missing required auth headers",
        required: [
          "x-api-key",
          "x-timestamp",
          "x-nonce",
          "x-asset-id",
          "x-signature",
        ],
      });
    }

    if (signatureVersion !== SIGNATURE_VERSION) {
      return res.status(401).json({
        success: false,
        error: "Unsupported signature version",
      });
    }

    if (nonce.length < 16 || nonce.length > 128) {
      return res.status(401).json({
        success: false,
        error: "Invalid nonce",
      });
    }

    const timestampMs = Number.parseInt(timestamp, 10);

    if (!Number.isFinite(timestampMs)) {
      return res.status(401).json({
        success: false,
        error: "Invalid timestamp",
      });
    }

    const toleranceMs = Number(config.ingestSignatureToleranceMs || 5 * 60 * 1000);

    if (Math.abs(Date.now() - timestampMs) > toleranceMs) {
      return res.status(401).json({
        success: false,
        error: "Timestamp out of allowed range",
      });
    }

    const keyDoc = await APIKey.findOne({
      token,
      is_active: true,
    })
      .select("+secret_key_hash")
      .populate("_asset_id");

    if (!keyDoc) {
      return res.status(401).json({
        success: false,
        error: "Invalid API key",
      });
    }

    if (keyDoc.expires_at && keyDoc.expires_at < new Date()) {
      return res.status(401).json({
        success: false,
        error: "API key expired",
      });
    }

    if (!keyDoc._asset_id) {
      return res.status(401).json({
        success: false,
        error: "API key is not linked with an asset",
      });
    }

    const linkedAssetIdentity =
      keyDoc._asset_id.asset_id ||
      keyDoc._asset_id.assetId ||
      keyDoc._asset_id._id?.toString();

    if (String(linkedAssetIdentity) !== assetIdHeader) {
      return res.status(401).json({
        success: false,
        error: "Asset mismatch for API key",
      });
    }

    const signingKey = getSigningKeyFromStoredHash(keyDoc.secret_key_hash);

    const expectedSignature = buildSignature({
      signingKey,
      timestamp,
      nonce,
      assetId: assetIdHeader,
      body: req.body || {},
    });

    const signatureOk = safeCompare(signature, expectedSignature);

    if (!signatureOk) {
      return res.status(401).json({
        success: false,
        error: "Invalid request signature",
      });
    }

    const nonceAccepted = await reserveNonce({
      nonce,
      apiKeyToken: token,
      assetIdentifier: assetIdHeader,
      ttlMs: Number(config.ingestNonceTtlMs || toleranceMs),
    });

    if (!nonceAccepted) {
      return res.status(409).json({
        success: false,
        error: "Replay detected",
      });
    }

    req.orgId = keyDoc._org_id;
    req.org = { _id: keyDoc._org_id };

    req.assetId = keyDoc._asset_id._id;
    req.asset = keyDoc._asset_id;

    req.apiKey = keyDoc;
    req.signatureVersion = signatureVersion;

    keyDoc.last_used_at = new Date();
    keyDoc.last_used_ip = req.ip;
    keyDoc.usage_count = Number(keyDoc.usage_count || 0) + 1;

    await keyDoc.save();

    await Asset.updateOne(
      { _id: keyDoc._asset_id._id },
      {
        $set: {
          agent_last_seen: new Date(),
          agent_status: "online",
          agent_version:
            getHeader(req, "x-agent-version") ||
            keyDoc._asset_id.agent_version ||
            "unknown",
        },
      }
    ).catch(() => {});

    return next();
  } catch (error) {
    appLogger.error("Ingest authentication failed", serializeError(error));

    return res.status(500).json({
      success: false,
      error: "Ingest authentication failed",
    });
  }
};

const validateIngestPayload = (req, res, next) => {
  const { logs } = req.body || {};

  if (!Array.isArray(logs) || logs.length === 0) {
    return res.status(400).json({
      success: false,
      error: "Invalid payload",
      message: "logs array is required",
    });
  }

  const batchLimit = Number(config.ingestBatchLimit || 500);

  if (logs.length > batchLimit) {
    return res.status(413).json({
      success: false,
      error: "Batch too large",
      message: `Maximum batch size is ${batchLimit}`,
    });
  }

  for (let index = 0; index < logs.length; index += 1) {
    const log = logs[index];

    if (!log || typeof log !== "object" || Array.isArray(log)) {
      return res.status(400).json({
        success: false,
        error: "Invalid log format",
        index,
        message: "Each log entry must be an object",
      });
    }

    const hasMessage = String(log.message || "").trim();
    const hasEventType = String(log.eventType || log.event_type || "").trim();
    const hasSnortMessage = String(log.metadata?.snort?.message || "").trim();

    if (!hasMessage && !hasEventType && !hasSnortMessage) {
      return res.status(400).json({
        success: false,
        error: "Invalid log format",
        index,
        message: "message or eventType is required",
      });
    }
  }

  return next();
};

module.exports = {
  validateAPIKey,
  validateIngestPayload,
};