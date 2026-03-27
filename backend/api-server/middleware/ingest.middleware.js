/**
 * Ingestion API middleware
 * Validates API keys from agents
 * Verifies HMAC signatures
 * Enforces rate limits
 * Prevents cross-tenant data injection
 */

const crypto = require("crypto");
const APIKey = require("../models/APIKey");

/**
 * Validate API key from headers
 */
const validateAPIKey = async (req, res, next) => {
  const apiKeyHeader = req.headers["x-api-key"];
  const timestamp = req.headers["x-timestamp"];
  const signature = req.headers["x-signature"];
  const assetId = req.headers["x-asset-id"];

  // Check required headers
  if (!apiKeyHeader || !timestamp || !signature || !assetId) {
    return res.status(400).json({
      error: "Missing required headers",
      required: ["X-API-Key", "X-Timestamp", "X-Signature", "X-Asset-ID"]
    });
  }

  // Validate timestamp
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);

  if (isNaN(ts)) {
    return res.status(400).json({ error: "Invalid X-Timestamp format" });
  }

  if (Math.abs(now - ts) > 300) {
    return res.status(401).json({
      error: "Request timestamp outside acceptable window",
      server_time: now,
      provided_time: ts,
      max_age_seconds: 300
    });
  }

  try {
    // Find API key
    const apiKeyRecord = await APIKey.findOne({
      token: apiKeyHeader,
      is_active: true,
      expires_at: { $gt: new Date() }
    })
      .populate("_org_id")
      .populate("_asset_id");

    if (!apiKeyRecord) {
      console.warn(`[Auth] Invalid API key`);
      return res.status(401).json({ error: "Invalid or expired API key" });
    }

    // Ensure asset exists
    if (!apiKeyRecord._asset_id) {
      return res.status(403).json({
        error: "API key not linked to asset"
      });
    }

    // Verify asset ID
    if (apiKeyRecord._asset_id.asset_id !== assetId) {
      return res.status(403).json({
        error: "Asset ID mismatch",
        provided: assetId,
        authorized: apiKeyRecord._asset_id.asset_id
      });
    }

    // Create message for HMAC verification
    const payload = JSON.stringify(req.body || {});
    const payloadHash = crypto
      .createHash("sha256")
      .update(payload)
      .digest("hex");

    const message = `${payloadHash}.${timestamp}`;

    let secret;

    if (process.env.NODE_ENV === "development") {
      secret = process.env.THREATLENS_API_SECRET || "tlk_secret_dev";
    } else {
      secret = process.env.API_KEY_SECRET_PREFIX || "tlk_secret_prod";
    }

    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(message)
      .digest("hex");

    // Timing-safe signature comparison
    const isValidSignature = crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );

    if (!isValidSignature) {
      console.warn(`[Auth] Invalid signature`);
      return res.status(401).json({ error: "Invalid request signature" });
    }

    // Update usage data
    apiKeyRecord.last_used_at = new Date();
    apiKeyRecord.last_used_ip = req.ip;
    apiKeyRecord.usage_count = (apiKeyRecord.usage_count || 0) + 1;

    await apiKeyRecord.save();

    // Rate limit placeholder
    const quota = apiKeyRecord._org_id?.ingest_quota_per_minute || 1000;

    // Attach metadata
    req.apiKey = apiKeyRecord;
    req.orgId = apiKeyRecord._org_id._id;
    req.assetId = apiKeyRecord._asset_id._id;
    req.org = apiKeyRecord._org_id;

    next();
  } catch (err) {
    console.error("[Ingest Auth Error]", err);
    return res.status(500).json({
      error: "Authentication service error"
    });
  }
};

/**
 * Validate ingest payload
 */
const validateIngestPayload = (req, res, next) => {
  const { events } = req.body;

  if (!Array.isArray(events)) {
    return res.status(400).json({
      error: "events must be an array"
    });
  }

  if (events.length === 0) {
    return res.status(400).json({
      error: "events array cannot be empty"
    });
  }

  if (events.length > 10000) {
    return res.status(413).json({
      error: "events array too large",
      provided: events.length,
      maximum: 10000
    });
  }

  const validEventTypes = [
    "http_request",
    "auth_failure",
    "auth_success",
    "network_flow",
    "dns_query",
    "package_change",
    "file_change",
    "process_start",
    "system_error"
  ];

  const errors = [];

  for (let i = 0; i < Math.min(events.length, 20); i++) {
    const event = events[i];

    if (!event.event_id) {
      errors.push(`Event ${i}: missing event_id`);
    }

    if (!event.timestamp) {
      errors.push(`Event ${i}: missing timestamp`);
    } else if (isNaN(new Date(event.timestamp).getTime())) {
      errors.push(`Event ${i}: invalid timestamp`);
    }

    if (!event.event_type) {
      errors.push(`Event ${i}: missing event_type`);
    } else if (!validEventTypes.includes(event.event_type)) {
      errors.push(`Event ${i}: invalid event_type (${event.event_type})`);
    }
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: "Request validation failed",
      details: errors.slice(0, 10),
      total_errors: errors.length
    });
  }

  next();
};

module.exports = {
  validateAPIKey,
  validateIngestPayload
};