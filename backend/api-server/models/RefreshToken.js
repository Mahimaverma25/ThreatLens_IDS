const mongoose = require("mongoose");

const RefreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },

  // ✅ FIX: Add org reference (important for multi-tenant)
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  tokenHash: {
    type: String,
    required: true,
    unique: true, // 🔥 prevent duplicate tokens
    index: true
  },

  createdAt: {
    type: Date,
    default: Date.now
  },

  expiresAt: {
    type: Date,
    required: true
  },

  revokedAt: {
    type: Date,
    default: null, // ✅ IMPORTANT FIX
    index: true
  },

  replacedByTokenHash: {
    type: String
  }
});

/* 🔥 Auto-clean expired tokens (optional but powerful) */
RefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("RefreshToken", RefreshTokenSchema);