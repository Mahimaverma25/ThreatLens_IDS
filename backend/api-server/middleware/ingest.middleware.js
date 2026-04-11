/**
 * 🚀 ThreatLens Ingestion Middleware (UPDATED)
 */
const crypto = require("crypto");
const APIKey = require("../models/APIKey");

/* ================= API KEY VALIDATION ================= */

const validateAPIKey = async (req, res, next) => {
  try {
    const token = req.headers["x-api-key"];
    const secret = req.headers["x-api-secret"];
    const timestamp = req.headers["x-timestamp"];
    const signature = req.headers["x-signature"];
    const assetIdHeader = req.headers["x-asset-id"];

    if (!token || !secret || !timestamp || !signature || !assetIdHeader) {
      return res.status(401).json({
        error: "Missing required auth headers",
      });
    }

    const timestampMs = Number.parseInt(timestamp, 10);
    if (Number.isNaN(timestampMs)) {
      return res.status(401).json({ error: "Invalid timestamp" });
    }

    const now = Date.now();
    const skewMs = Math.abs(now - timestampMs);
    if (skewMs > 5 * 60 * 1000) {
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

    const secretHash = crypto.createHash("sha256").update(secret).digest("hex");
    if (secretHash !== keyDoc.secret_key_hash) {
      return res.status(401).json({ error: "Invalid API secret" });
    }

    if (!keyDoc._asset_id || keyDoc._asset_id.asset_id !== assetIdHeader) {
      return res.status(401).json({ error: "Asset mismatch for API key" });
    }

    const payload = JSON.stringify(req.body || {});
    const signedContent = `${timestamp}.${payload}`;
    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(signedContent)
      .digest("hex");

    if (signature.length !== expectedSignature.length) {
      return res.status(401).json({ error: "Invalid request signature" });
    }

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
      return res.status(401).json({ error: "Invalid request signature" });
    }

    req.orgId = keyDoc._org_id;
    req.assetId = keyDoc._asset_id._id;

    keyDoc.last_used_at = new Date();
    keyDoc.last_used_ip = req.ip;
    keyDoc.usage_count = (keyDoc.usage_count || 0) + 1;
    await keyDoc.save();

    next();
  } catch (error) {
    console.error("[Ingest Auth Error]", error);
    return res.status(500).json({ error: "Ingest authentication failed" });
  }
};

/* ================= PAYLOAD VALIDATION ================= */

const validateIngestPayload = (req, res, next) => {
  const { logs } = req.body;

  // ✅ Check logs array
  if (!logs || !Array.isArray(logs)) {
    return res.status(400).json({
      error: "Invalid payload",
      message: "logs array is required",
    });
  }

  // ✅ Validate each log
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];

    if (!log.message || !log.level || !log.timestamp) {
      return res.status(400).json({
        error: "Invalid log format",
        index: i,
        required: ["message", "level", "timestamp"],
      });
    }
  }

  next();
};

module.exports = {
  validateAPIKey,
  validateIngestPayload,
};
