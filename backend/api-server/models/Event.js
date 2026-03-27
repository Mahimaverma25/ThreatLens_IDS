const mongoose = require("mongoose");

const EventSchema = new mongoose.Schema({
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  _asset_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Asset",
    required: true,
    index: true
  },

  _batch_id: String,

  _ingested_at: {
    type: Date,
    default: Date.now
  },

  _processed: {
    type: Boolean,
    default: false
  },

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

  source_ip: {
    type: String,
    index: true
  },

  dest_ip: String,
  source_port: Number,
  dest_port: Number,
  protocol: String,

  http_method: String,
  http_path: String,
  http_status: Number,
  http_host: String,
  http_user_agent: String,
  http_referer: String,
  http_headers: mongoose.Schema.Types.Mixed,

  user: {
    type: String,
    index: true
  },

  auth_success: Boolean,
  auth_method: String,

  payload_size: Number,
  payload_hash: String,

  action: String,

  raw: String,

  created_at: {
    type: Date,
    default: Date.now,
    index: { expireAfterSeconds: 2592000 }
  }
});

EventSchema.index({ _org_id: 1, timestamp: -1 });
EventSchema.index({ _org_id: 1, _asset_id: 1, timestamp: -1 });
EventSchema.index({ _org_id: 1, source_ip: 1, timestamp: -1 });
EventSchema.index({ _org_id: 1, user: 1, timestamp: -1 });

module.exports = mongoose.model("Event", EventSchema);