const APIKey = require("../models/APIKey");
const Asset = require("../models/Asset");
const AuditLog = require("../models/AuditLog");

const getUserId = (req) => req.user?.sub || req.user?._id || req.user?.id || null;

const toPositiveNumber = (value, fallback = null) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const buildExpiryDate = (expirationDays) => {
  const days = toPositiveNumber(expirationDays);

  if (!days) {
    return new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  }

  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
};

const maskToken = (token = "") => {
  const value = String(token);
  if (value.length <= 16) return value;
  return `${value.slice(0, 12)}...${value.slice(-6)}`;
};

const writeAuditLog = async ({ req, action, success = true, metadata = {} }) => {
  await AuditLog.create({
    action,
    userId: getUserId(req),
    _org_id: req.orgId,
    ip: req.ip,
    success,
    metadata,
  }).catch(() => {});
};

const formatAPIKey = (apiKey) => ({
  _id: apiKey._id,
  token: apiKey.token,
  masked_token: maskToken(apiKey.token),
  key_name: apiKey.key_name,
  permissions: apiKey.permissions,
  asset: apiKey._asset_id,
  is_active: apiKey.is_active,
  created_at: apiKey.created_at,
  created_by: apiKey.created_by,
  expires_at: apiKey.expires_at,
  last_used_at: apiKey.last_used_at,
  last_used_ip: apiKey.last_used_ip,
  usage_count: apiKey.usage_count,
  revoked_at: apiKey.revoked_at,
  is_expired: Boolean(apiKey.expires_at && apiKey.expires_at < new Date()),
});

const generateAPIKey = async (req, res) => {
  try {
    const { asset_id, key_name, expiration_days, permissions } = req.body;

    if (!asset_id) {
      return res.status(400).json({
        success: false,
        message: "asset_id is required",
      });
    }

    const asset = await Asset.findOne({
      _id: asset_id,
      _org_id: req.orgId,
    });

    if (!asset) {
      return res.status(404).json({
        success: false,
        message: "Asset not found",
      });
    }

    const generated = APIKey.generate(req.orgId);

    const apiKey = await APIKey.create({
      token: generated.token,
      secret_key_hash: generated.secret_key_hash,
      _org_id: req.orgId,
      _asset_id: asset._id,
      key_name: key_name || `Agent Key - ${asset.asset_name || asset.asset_id}`,
      permissions:
        Array.isArray(permissions) && permissions.length > 0
          ? permissions
          : ["logs:ingest", "agent:heartbeat"],
      created_by: getUserId(req),
      expires_at: buildExpiryDate(expiration_days),
      is_active: true,
    });

    await writeAuditLog({
      req,
      action: "apikey.generate",
      metadata: {
        asset_id: asset._id.toString(),
        asset_identity: asset.asset_id,
        key_name: apiKey.key_name,
        apikey_id: apiKey._id.toString(),
      },
    });

    return res.status(201).json({
      success: true,
      message: "API key generated successfully",
      apiKey: {
        _id: apiKey._id,
        token: generated.token,
        secret: generated.secret,
        key_name: apiKey.key_name,
        permissions: apiKey.permissions,
        asset: {
          _id: asset._id,
          asset_id: asset.asset_id,
          asset_name: asset.asset_name,
        },
        created_at: apiKey.created_at,
        expires_at: apiKey.expires_at,
      },
      warning: "Save this secret now. It will not be shown again.",
    });
  } catch (error) {
    console.error("GENERATE API KEY ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to generate API key",
    });
  }
};

const listAPIKeys = async (req, res) => {
  try {
    const apiKeys = await APIKey.find({
      _org_id: req.orgId,
    })
      .select("-secret_key_hash")
      .populate("_asset_id", "asset_id asset_name hostname agent_status")
      .sort({ created_at: -1 });

    const keys = apiKeys.map(formatAPIKey);

    return res.json({
      success: true,
      data: keys,
      total: keys.length,
    });
  } catch (error) {
    console.error("LIST API KEYS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch API keys",
    });
  }
};

const getAPIKey = async (req, res) => {
  try {
    const { id } = req.params;

    const apiKey = await APIKey.findOne({
      _id: id,
      _org_id: req.orgId,
    })
      .select("-secret_key_hash")
      .populate("_asset_id", "asset_id asset_name hostname agent_status");

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found",
      });
    }

    return res.json({
      success: true,
      data: formatAPIKey(apiKey),
    });
  } catch (error) {
    console.error("GET API KEY ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch API key",
    });
  }
};

const revokeAPIKey = async (req, res) => {
  try {
    const { id } = req.params;

    const apiKey = await APIKey.findOne({
      _id: id,
      _org_id: req.orgId,
    });

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found",
      });
    }

    apiKey.is_active = false;
    apiKey.revoked_at = new Date();
    apiKey.revoked_by = getUserId(req);

    await apiKey.save();

    await writeAuditLog({
      req,
      action: "apikey.revoke",
      metadata: {
        apikey_id: apiKey._id.toString(),
        key_name: apiKey.key_name,
      },
    });

    return res.json({
      success: true,
      message: "API key revoked successfully",
      data: {
        _id: apiKey._id,
        key_name: apiKey.key_name,
        revoked_at: apiKey.revoked_at,
      },
    });
  } catch (error) {
    console.error("REVOKE API KEY ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to revoke API key",
    });
  }
};

const rotateAPIKey = async (req, res) => {
  try {
    const { id } = req.params;
    const { expiration_days } = req.body;

    const apiKey = await APIKey.findOne({
      _id: id,
      _org_id: req.orgId,
      is_active: true,
    }).populate("_asset_id", "asset_id asset_name hostname agent_status");

    if (!apiKey) {
      return res.status(404).json({
        success: false,
        message: "API key not found or already revoked",
      });
    }

    const newSecret = require("crypto").randomBytes(32).toString("hex");

    apiKey.secret_key_hash = APIKey.hashSecret(newSecret);
    apiKey.rotated_at = new Date();
    apiKey.rotated_by = getUserId(req);

    if (expiration_days) {
      apiKey.expires_at = buildExpiryDate(expiration_days);
    }

    await apiKey.save();

    await writeAuditLog({
      req,
      action: "apikey.rotate",
      metadata: {
        apikey_id: apiKey._id.toString(),
        key_name: apiKey.key_name,
      },
    });

    return res.json({
      success: true,
      message: "API key rotated successfully",
      apiKey: {
        _id: apiKey._id,
        token: apiKey.token,
        secret: newSecret,
        key_name: apiKey.key_name,
        permissions: apiKey.permissions,
        asset: apiKey._asset_id,
        rotated_at: apiKey.rotated_at,
        expires_at: apiKey.expires_at,
      },
      warning: "Save this new secret now. It will not be shown again.",
    });
  } catch (error) {
    console.error("ROTATE API KEY ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to rotate API key",
    });
  }
};

module.exports = {
  generateAPIKey,
  listAPIKeys,
  getAPIKey,
  revokeAPIKey,
  rotateAPIKey,
};