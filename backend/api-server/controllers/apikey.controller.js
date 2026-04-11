const APIKey = require("../models/APIKey");
const Asset = require("../models/Asset");
const AuditLog = require("../models/AuditLog");
const crypto = require("crypto");

/**
 * Generate a new API key for an asset
 * Admin only endpoint - creates API key that agent will use to authenticate
 * POST /api/admin/api-keys
 * Body: { asset_id, key_name, expiration_days }
 */
const generateAPIKey = async (req, res) => {
  try {
    const { asset_id, key_name, expiration_days } = req.body;

    if (!asset_id || !key_name) {
      return res.status(400).json({ message: "asset_id and key_name are required" });
    }

    // Verify asset belongs to this organization
    const asset = await Asset.findOne({
      _id: asset_id,
      _org_id: req.orgId
    });

    if (!asset) {
      return res.status(404).json({ message: "Asset not found" });
    }

    // Generate new API key with token + secret
    const { token, secret } = APIKey.generate();

    // Create API key record
    const apiKey = await APIKey.create({
      token,
      secret_key_hash: crypto.createHash("sha256").update(secret).digest("hex"),
      _org_id: req.orgId,
      _asset_id: asset_id,
      key_name,
      created_by: req.user.sub,
      expires_at: expiration_days 
        ? new Date(Date.now() + expiration_days * 24 * 60 * 60 * 1000)
        : null,
      is_active: true
    });

    // Audit log
    await AuditLog.create({
      action: "apikey.generate",
      userId: req.user.sub,
      _org_id: req.orgId,
      ip: req.ip,
      success: true,
      metadata: {
        asset_id,
        key_name,
        apikey_id: apiKey._id.toString()
      }
    });

    // Return secret ONLY in response (cannot be retrieved later)
    return res.status(201).json({
      message: "API key generated successfully",
      apiKey: {
        _id: apiKey._id,
        token, // Public token
        secret, // Secret - show only once, user must save it
        key_name,
        asset_id,
        created_at: apiKey.created_at,
        expires_at: apiKey.expires_at
      }
    });
  } catch (error) {
    console.error("GENERATE API KEY ERROR:", error);
    return res.status(500).json({ message: "Failed to generate API key" });
  }
};

/**
 * List all API keys for organization
 * GET /api/admin/api-keys
 */
const listAPIKeys = async (req, res) => {
  try {
    const apiKeys = await APIKey.find({
      _org_id: req.orgId
    })
      .select("-secret_key_hash") // Never expose hash
      .populate("_asset_id", "asset_id asset_name")
      .sort({ createdAt: -1 });

    // Add useful computed fields
    const keys = apiKeys.map(key => ({
      _id: key._id,
      token: key.token,
      key_name: key.key_name,
      asset: key._asset_id,
      is_active: key.is_active,
      created_at: key.createdAt,
      created_by: key.created_by,
      expires_at: key.expires_at,
      last_used_at: key.last_used_at,
      usage_count: key.usage_count,
      is_expired: key.expires_at && key.expires_at < new Date()
    }));

    return res.json({
      data: keys,
      total: keys.length
    });
  } catch (error) {
    console.error("LIST API KEYS ERROR:", error);
    return res.status(500).json({ message: "Failed to fetch API keys" });
  }
};

/**
 * Get single API key details (non-sensitive fields)
 * GET /api/admin/api-keys/:id
 */
const getAPIKey = async (req, res) => {
  try {
    const { id } = req.params;

    const apiKey = await APIKey.findOne({
      _id: id,
      _org_id: req.orgId
    })
      .select("-secret_key_hash")
      .populate("_asset_id", "asset_id asset_name");

    if (!apiKey) {
      return res.status(404).json({ message: "API key not found" });
    }

    return res.json({
      _id: apiKey._id,
      token: apiKey.token,
      key_name: apiKey.key_name,
      asset: apiKey._asset_id,
      is_active: apiKey.is_active,
      created_at: apiKey.created_at,
      created_by: apiKey.created_by,
      expires_at: apiKey.expires_at,
      last_used_at: apiKey.last_used_at,
      usage_count: apiKey.usage_count,
      is_expired: apiKey.expires_at && apiKey.expires_at < new Date()
    });
  } catch (error) {
    console.error("GET API KEY ERROR:", error);
    return res.status(500).json({ message: "Failed to fetch API key" });
  }
};

/**
 * Revoke/deactivate an API key
 * DELETE /api/admin/api-keys/:id
 */
const revokeAPIKey = async (req, res) => {
  try {
    const { id } = req.params;

    const apiKey = await APIKey.findOneAndUpdate(
      { _id: id, _org_id: req.orgId },
      {
        is_active: false,
        revoked_at: new Date(),
        revoked_by: req.user.sub
      },
      { new: true }
    );

    if (!apiKey) {
      return res.status(404).json({ message: "API key not found" });
    }

    // Audit log
    await AuditLog.create({
      action: "apikey.revoke",
      userId: req.user.sub,
      _org_id: req.orgId,
      ip: req.ip,
      success: true,
      metadata: {
        apikey_id: apiKey._id.toString(),
        key_name: apiKey.key_name
      }
    });

    return res.json({
      message: "API key revoked successfully",
      _id: apiKey._id,
      key_name: apiKey.key_name,
      revoked_at: apiKey.revoked_at
    });
  } catch (error) {
    console.error("REVOKE API KEY ERROR:", error);
    return res.status(500).json({ message: "Failed to revoke API key" });
  }
};

/**
 * Rotate API key - generate new secret for existing token
 * POST /api/admin/api-keys/:id/rotate
 */
const rotateAPIKey = async (req, res) => {
  try {
    const { id } = req.params;
    const { expiration_days } = req.body;

    const apiKey = await APIKey.findOne({
      _id: id,
      _org_id: req.orgId,
      is_active: true
    });

    if (!apiKey) {
      return res.status(404).json({ message: "API key not found or already revoked" });
    }

    // Generate new secret
    const { secret: newSecret } = APIKey.generate();

    // Update key
    apiKey.secret_key_hash = crypto.createHash("sha256").update(newSecret).digest("hex");
    apiKey.rotated_at = new Date();
    apiKey.rotated_by = req.user.sub;
    if (expiration_days) {
      apiKey.expires_at = new Date(Date.now() + expiration_days * 24 * 60 * 60 * 1000);
    }
    await apiKey.save();

    // Audit log
    await AuditLog.create({
      action: "apikey.rotate",
      userId: req.user.sub,
      _org_id: req.orgId,
      ip: req.ip,
      success: true,
      metadata: {
        apikey_id: apiKey._id.toString(),
        key_name: apiKey.key_name
      }
    });

    return res.json({
      message: "API key rotated successfully",
      _id: apiKey._id,
      token: apiKey.token,
      secret: newSecret, // New secret - show only once
      key_name: apiKey.key_name,
      rotated_at: apiKey.rotated_at,
      expires_at: apiKey.expires_at
    });
  } catch (error) {
    console.error("ROTATE API KEY ERROR:", error);
    return res.status(500).json({ message: "Failed to rotate API key" });
  }
};

module.exports = {
  generateAPIKey,
  listAPIKeys,
  getAPIKey,
  revokeAPIKey,
  rotateAPIKey
};
