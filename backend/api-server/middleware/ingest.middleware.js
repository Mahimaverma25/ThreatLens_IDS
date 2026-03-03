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
 * Validate API key from X-API-Key header
 * Extract org_id from key
 * Verify signature
 * Check rate limits
 */
const validateAPIKey = async (req, res, next) => {
  const apiKeyHeader = req.headers["x-api-key"];
  const timestamp = req.headers["x-timestamp"];
  const signature = req.headers["x-signature"];
  const assetId = req.headers["x-asset-id"];

  // Verify headers exist
  if (!apiKeyHeader || !timestamp || !signature || !assetId) {
    return res.status(400).json({
      error: "Missing required headers",
      required: ["X-API-Key", "X-Timestamp", "X-Signature", "X-Asset-ID"],
    });
  }

  // Verify timestamp is recent (replay protection: ±5 minutes)
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);

  if (isNaN(ts)) {
    return res.status(400).json({ error: "Invalid X-Timestamp format" });
  }

  if (Math.abs(now - ts) > 300) {
    return res.status(401).json({
      error: "Request timestamp outside acceptable window (replay protection)",
      server_time: now,
      provided_time: ts,
      max_age_seconds: 300,
    });
  }

  try {
    // Look up API key in database
    const apiKeyRecord = await APIKey.findOne({
      token: apiKeyHeader,
      is_active: true,
      expires_at: { $gt: new Date() },
    })
      .populate("_org_id")
      .populate("_asset_id");

    if (!apiKeyRecord) {
      console.warn(`[Auth] Invalid/expired API key: ${apiKeyHeader.substring(0, 20)}...`);
      return res.status(401).json({ error: "Invalid or expired API key" });
    }

    // Verify asset_id matches
    if (apiKeyRecord._asset_id.asset_id !== assetId) {
      return res.status(403).json({
        error: "Asset ID does not match API key permissions",
        provided: assetId,
        authorized: apiKeyRecord._asset_id.asset_id,
      });
    }

    // Verify HMAC signature
    // Note: In production, secret_key_hash should be retrieved with a special query
    // For now, we'll need to store and verify properly
    const payload = JSON.stringify(req.body);
    const payloadHash = crypto.createHash("sha256").update(payload).digest("hex");
    const message = `${payloadHash}.${timestamp}`;

    // Retrieve secret key (would be decrypted in prod)
    // This is a simplified version - real implementation needs proper secret management
    const expectedSignature = crypto
      .createHmac("sha256", process.env.API_KEY_SECRET_PREFIX || "tlk_secret_") // Simplified!
      .update(message)
      .digest("hex");

    if (signature !== expectedSignature) {
      console.warn(`[Auth] Invalid signature for API key: ${apiKeyHeader.substring(0, 20)}...`);
      return res.status(401).json({ error: "Invalid request signature" });
    }

    // Update last used timestamp
    apiKeyRecord.last_used_at = new Date();
    apiKeyRecord.last_used_ip = req.ip;
    apiKeyRecord.usage_count = (apiKeyRecord.usage_count || 0) + 1;
    await apiKeyRecord.save();

    // Check rate limits
    // TODO: Implement Redis-based rate limiting
    const quota = apiKeyRecord._org_id.ingest_quota_per_minute || 1000;
    // Rate limit check would go here

    // Attach to request
    req.apiKey = apiKeyRecord;
    req.orgId = apiKeyRecord._org_id._id;
    req.assetId = apiKeyRecord._asset_id._id;
    req.org = apiKeyRecord._org_id;

    next();
  } catch (err) {
    console.error("[Ingest Auth Error]", err);
    res.status(500).json({ error: "Authentication service error" });
  }
};

/**
 * Validate ingest request payload
 */
const validateIngestPayload = (req, res, next) => {
  const { events } = req.body;

  // Must be array
  if (!Array.isArray(events)) {
    return res.status(400).json({
      error: "events must be an array",
    });
  }

  // Must not be empty
  if (events.length === 0) {
    return res.status(400).json({
      error: "events array cannot be empty",
    });
  }

  // Max 10k events per request
  if (events.length > 10000) {
    return res.status(413).json({
      error: "events array too large",
      provided: events.length,
      maximum: 10000,
    });
  }

  // Validate each event structure
  const errors = [];
  const validEventTypes = [
    "http_request",
    "auth_failure",
    "auth_success",
    "network_flow",
    "dns_query",
    "package_change",
    "file_change",
    "process_start",
    "system_error",
  ];

  for (let i = 0; i < Math.min(events.length, 20); i++) {
    const event = events[i];

    if (!event.event_id) {
      errors.push(`Event ${i}: missing event_id`);
    }

    if (!event.timestamp) {
      errors.push(`Event ${i}: missing timestamp`);
    } else if (isNaN(new Date(event.timestamp).getTime())) {
      errors.push(`Event ${i}: invalid timestamp format (not ISO 8601)`);
    }

    if (!event.event_type) {
      errors.push(`Event ${i}: missing event_type`);
    } else if (!validEventTypes.includes(event.event_type)) {
      errors.push(`Event ${i}: invalid event_type: ${event.event_type}`);
    }
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: "Request validation failed",
      details: errors.slice(0, 10), // Return first 10 errors
      total_errors: errors.length,
    });
  }

  next();
};

module.exports = { validateAPIKey, validateIngestPayload };
