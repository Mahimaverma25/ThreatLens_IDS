const mongoose = require("mongoose");

const LogSchema = new mongoose.Schema({
  // Multi-tenant field - CRITICAL
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  // Asset this log is about (optional)
  _asset_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Asset",
    index: true
  },

  message: { type: String, required: true, trim: true },
  level: { type: String, default: "info", trim: true, index: true },
  source: { type: String, default: "api", trim: true },
  ip: { type: String, trim: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  endpoint: { type: String, trim: true },
  method: { type: String, trim: true },
  statusCode: { type: Number },
  eventType: { type: String, trim: true },
  metadata: { type: Object, default: {} },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

// Indexes for multi-tenant queries
LogSchema.index({ _org_id: 1, timestamp: -1 });
LogSchema.index({ _org_id: 1, level: 1 });
LogSchema.index({ _org_id: 1, _asset_id: 1, timestamp: -1 });

module.exports = mongoose.model("Log", LogSchema);
