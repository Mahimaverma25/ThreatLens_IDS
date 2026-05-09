const mongoose = require("mongoose");
const crypto = require("crypto");

const DEFAULT_PERMISSIONS = ["logs:ingest", "agent:heartbeat"];

const APIKeySchema = new mongoose.Schema(
  {
    _org_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
      required: true,
      index: true,
    },

    _asset_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Asset",
      required: true,
      index: true,
    },

    token: {
      type: String,
      unique: true,
      required: true,
      trim: true,
      index: true,
    },

    /**
     * Stores SHA-256(secret).hex
     *
     * Compatible with agent/apiClient.js:
     * getSigningKey(secret) = sha256(secret).hex
     */
    secret_key_hash: {
      type: String,
      required: true,
      select: false,
    },

    key_name: {
      type: String,
      trim: true,
      default: "ThreatLens Agent Key",
    },

    permissions: {
      type: [String],
      default: DEFAULT_PERMISSIONS,
    },

    last_used_at: Date,
    last_used_ip: String,

    usage_count: {
      type: Number,
      default: 0,
      min: 0,
    },

    is_active: {
      type: Boolean,
      default: true,
      index: true,
    },

    revoked_at: Date,

    expires_at: {
      type: Date,
      default: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      index: true,
    },

    created_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  {
    timestamps: {
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
  }
);

APIKeySchema.statics.hashSecret = function (secret) {
  return crypto
    .createHash("sha256")
    .update(String(secret || ""), "utf8")
    .digest("hex");
};

APIKeySchema.statics.generate = function (orgId) {
  const orgSuffix = orgId
    ? orgId.toString().slice(-8)
    : crypto.randomBytes(4).toString("hex");

  const token = `tlk_${orgSuffix}_${crypto.randomBytes(16).toString("hex")}`;
  const secret = crypto.randomBytes(32).toString("hex");

  return {
    token,
    secret,
    secret_key_hash: this.hashSecret(secret),
  };
};

APIKeySchema.methods.isExpired = function () {
  return Boolean(this.expires_at && this.expires_at.getTime() < Date.now());
};

APIKeySchema.methods.canUse = function () {
  return Boolean(this.is_active && !this.revoked_at && !this.isExpired());
};

APIKeySchema.methods.verifySecret = function (secret) {
  if (!this.secret_key_hash || !secret) return false;

  const incomingHash = this.constructor.hashSecret(secret);

  const storedBuffer = Buffer.from(this.secret_key_hash, "hex");
  const incomingBuffer = Buffer.from(incomingHash, "hex");

  if (storedBuffer.length !== incomingBuffer.length) return false;

  return crypto.timingSafeEqual(storedBuffer, incomingBuffer);
};

APIKeySchema.methods.hasPermission = function (permission) {
  if (!permission) return false;
  return Array.isArray(this.permissions) && this.permissions.includes(permission);
};

APIKeySchema.methods.markUsed = async function (ip) {
  this.last_used_at = new Date();
  this.last_used_ip = ip;
  this.usage_count = Number(this.usage_count || 0) + 1;
  return this.save();
};

APIKeySchema.methods.revoke = async function () {
  this.is_active = false;
  this.revoked_at = new Date();
  return this.save();
};

APIKeySchema.index({ _org_id: 1, is_active: 1 });
APIKeySchema.index({ _org_id: 1, _asset_id: 1 });
APIKeySchema.index({ token: 1, is_active: 1 });

module.exports = mongoose.model("APIKey", APIKeySchema);