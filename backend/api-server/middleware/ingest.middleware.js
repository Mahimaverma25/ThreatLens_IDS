const crypto = require("crypto");

const APIKey = require("../models/APIKey");
const Asset = require("../models/Asset");
const config = require("../config/env");
const { reserveNonce } = require("../services/ingestNonce.service");
const { appLogger, serializeError } = require("../utils/logger");
const {
  SIGNATURE_VERSION,
  buildPayloadHash,
  buildSignatureFromSigningKey,
} = require("../utils/ingestSignature");

const isValidSignature = (provided, expected) => {
  if (!provided || !expected || provided.length !== expected.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
};

const validateAPIKey = async (req, res, next) => {
  try {
    const token = req.headers["x-api-key"];
    const timestamp = req.headers["x-timestamp"];
    const signature = req.headers["x-signature"];
    const nonce = String(req.headers["x-nonce"] || "").trim();
    const assetIdHeader = req.headers["x-asset-id"];
    const signatureVersion = req.headers["x-signature-version"] || SIGNATURE_VERSION;

    if (!token || !timestamp || !signature || !assetIdHeader || !nonce) {
      return res.status(401).json({
        error: "Missing required auth headers",
      });
    }

    if (nonce.length < 16 || nonce.length > 128) {
      return res.status(401).json({ error: "Invalid nonce" });
    }

    const timestampMs = Number.parseInt(timestamp, 10);
    if (Number.isNaN(timestampMs)) {
      return res.status(401).json({ error: "Invalid timestamp" });
    }

    const now = Date.now();
    if (Math.abs(now - timestampMs) > config.ingestSignatureToleranceMs) {
      return res.status(401).json({ error: "Timestamp out of allowed range" });
    }

    const keyDoc = await APIKey.findOne({ token, is_active: true })
      .select("+secret_key_hash")
      .populate("_asset_id");
    if (!keyDoc) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    if (keyDoc.expires_at && keyDoc.expires_at < new Date()) {
      return res.status(401).json({ error: "API key expired" });
    }

    if (!keyDoc._asset_id || keyDoc._asset_id.asset_id !== assetIdHeader) {
      return res.status(401).json({ error: "Asset mismatch for API key" });
    }

    const payloadHash = buildPayloadHash(req.body || {}, req.rawBody || "");
    const expectedV2Signature = buildSignatureFromSigningKey({
      signingKey: keyDoc.secret_key_hash,
      timestamp,
      nonce,
      assetId: assetIdHeader,
      payloadHash,
    });

    if (signatureVersion !== SIGNATURE_VERSION) {
      return res.status(401).json({ error: "Unsupported signature version" });
    }

    const signatureOk = isValidSignature(signature, expectedV2Signature);

    if (!signatureOk) {
      return res.status(401).json({ error: "Invalid request signature" });
    }

    const nonceAccepted = await reserveNonce({
      nonce,
      apiKeyToken: token,
      assetIdentifier: assetIdHeader,
      ttlMs: config.ingestNonceTtlMs,
    });

    if (!nonceAccepted) {
      return res.status(409).json({ error: "Replay detected" });
    }

    req.orgId = keyDoc._org_id;
    req.org = { _id: keyDoc._org_id };
    req.assetId = keyDoc._asset_id._id;
    req.asset = keyDoc._asset_id;
    req.apiKey = keyDoc;
    req.signatureVersion = signatureVersion;

    keyDoc.last_used_at = new Date();
    keyDoc.last_used_ip = req.ip;
    keyDoc.usage_count = (keyDoc.usage_count || 0) + 1;
    await keyDoc.save();

    await Asset.updateOne(
      { _id: keyDoc._asset_id._id },
      {
        $set: {
          agent_last_seen: new Date(),
          agent_status: "online",
          agent_version: req.headers["x-agent-version"] || keyDoc._asset_id.agent_version || "unknown",
        },
      }
    ).catch(() => {});

    next();
  } catch (error) {
    appLogger.error("Ingest authentication failed", serializeError(error));
    return res.status(500).json({ error: "Ingest authentication failed" });
  }
};

const validateIngestPayload = (req, res, next) => {
  const { logs } = req.body || {};

  if (!Array.isArray(logs) || logs.length === 0) {
    return res.status(400).json({
      error: "Invalid payload",
      message: "logs array is required",
    });
  }

  if (logs.length > config.ingestBatchLimit) {
    return res.status(413).json({
      error: "Batch too large",
      message: `Maximum batch size is ${config.ingestBatchLimit}`,
    });
  }

  for (let index = 0; index < logs.length; index += 1) {
    const log = logs[index];

    if (!log || typeof log !== "object") {
      return res.status(400).json({
        error: "Invalid log format",
        index,
        message: "Each log entry must be an object",
      });
    }

    if (!String(log.message || "").trim()) {
      return res.status(400).json({
        error: "Invalid log format",
        index,
        message: "message is required",
      });
    }
  }

  next();
};

module.exports = {
  validateAPIKey,
  validateIngestPayload,
};
