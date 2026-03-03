const mongoose = require("mongoose");

const EventSchema = new mongoose.Schema({
  // Multi-tenant field - CRITICAL
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  // Asset that generated this event
  _asset_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Asset",
    required: true,
    index: true
  },

  // Batch information
  _batch_id: String,
  _ingested_at: {
    type: Date,
    default: Date.now
  },

  // Processing flag
  _processed: {
    type: Boolean,
    default: false
  },

  // Event metadata from agent
  event_id: {
    type: String,
    unique: true,
    required: true
  },

  timestamp: {
    type: Date,
    required: true,
    index: true
  },

  event_type: {
    type: String,
    required: true,
    enum: [
      "http_request",
      "auth_failure",
      "auth_success",
      "network_flow",
      "dns_query",
      "package_change",
      "file_change",
      "process_start",
      "system_error",
      "other"
    ]
  },

  // Network info
  source_ip: {
    type: String,
    index: true
  },
  dest_ip: String,
  source_port: Number,
  dest_port: Number,
  protocol: String, // TCP, UDP, ICMP

  // HTTP specific
  http_method: String,
  http_path: String,
  http_status: Number,
  http_host: String,
  http_user_agent: String,
  http_referer: String,
  http_headers: mongoose.Schema.Types.Mixed,

  // Authentication
  user: {
    type: String,
    index: true
  },
  auth_success: Boolean,
  auth_method: String,

  // Data
  payload_size: Number,
  payload_hash: String, // SHA256 (not storing raw for privacy)

  // Status
  action: String, // allow, deny, drop

  // Raw log line (optional, for debugging)
  raw: String,

  // TTL Index: Auto-delete after 30 days
  created_at: {
    type: Date,
    default: Date.now,
    index: { expireAfterSeconds: 2592000 } // 30 days
  }
});

// CRITICAL: Indexes for multi-tenant queries
EventSchema.index({ _org_id: 1, timestamp: -1 });
EventSchema.index({ _org_id: 1, _asset_id: 1, timestamp: -1 });
EventSchema.index({ _org_id: 1, source_ip: 1, timestamp: -1 });
EventSchema.index({ _org_id: 1, user: 1, timestamp: -1 });

module.exports = mongoose.model("Event", EventSchema);
