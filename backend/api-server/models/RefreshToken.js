const mongoose = require("mongoose");

const RefreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  tokenHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  revokedAt: { type: Date },
  replacedByTokenHash: { type: String }
});

module.exports = mongoose.model("RefreshToken", RefreshTokenSchema);
