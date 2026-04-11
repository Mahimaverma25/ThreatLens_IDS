const mongoose = require("mongoose");
const crypto = require("crypto");

const APIKeySchema = new mongoose.Schema({
  // Link to organization
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  // Link to asset (server being monitored)
  _asset_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Asset",
    required: true
  },

  // Public token (shown once during creation)
  // Format: tlk_[org_id]_[random]
  token: {
    type: String,
    unique: true,
    required: true,
    index: true
  },

  // Secret key for HMAC signing (hashed for storage)
  secret_key_hash: {
    type: String,
    required: true,
    select: false // Never send to frontend
  },

  // Friendly name for this key
  key_name: {
    type: String,
    trim: true
  },

  // Tracking usage
  last_used_at: Date,
  last_used_ip: String,
  usage_count: {
    type: Number,
    default: 0
  },

  // Expiration
  is_active: {
    type: Boolean,
    default: true,
    index: true
  },

  expires_at: {
    type: Date,
    default: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
    index: true
  },

  // Audit trail
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  created_at: {
    type: Date,
    default: Date.now,
    immutable: true
  }
});

// Generate token and secret when creating new key
APIKeySchema.statics.generate = function(org_id, asset_id, name) {
  const token = `tlk_${org_id.toString().slice(-8)}_${crypto.randomBytes(16).toString("hex")}`;
  const secret = crypto.randomBytes(32).toString("hex");
  const secret_hash = crypto.createHash("sha256").update(secret).digest("hex");

  return {
    token,
    secret, // Return raw secret once - user must save it
    secret_key_hash: secret_hash
  };
};

// Verify HMAC signature
APIKeySchema.methods.verifySignature = function(payload, secret, signature) {
  const computed = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(signature));
};

// Indexes
APIKeySchema.index({ _org_id: 1, is_active: 1 });
APIKeySchema.index({ _org_id: 1, _asset_id: 1 });

module.exports = mongoose.model("APIKey", APIKeySchema);
