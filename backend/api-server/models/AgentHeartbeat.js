const mongoose = require("mongoose");

const AgentHeartbeatSchema = new mongoose.Schema(
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
    agent_type: {
      type: String,
      enum: ["nids", "hids", "hybrid", "unknown"],
      default: "hids",
      index: true,
    },
    asset_id: {
      type: String,
      trim: true,
      index: true,
    },
    hostname: {
      type: String,
      trim: true,
      default: "",
    },
    host_platform: {
      type: String,
      trim: true,
      default: "",
    },
    agent_version: {
      type: String,
      trim: true,
      default: "",
    },
    telemetry_types: [{ type: String, trim: true }],
    queue_depth: {
      type: Number,
      default: 0,
    },
    status: {
      type: String,
      enum: ["online", "offline", "error", "degraded"],
      default: "online",
      index: true,
    },
    ip: {
      type: String,
      trim: true,
      default: "",
    },
    metadata: {
      type: Object,
      default: {},
    },
    receivedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

AgentHeartbeatSchema.index({ _org_id: 1, _asset_id: 1, receivedAt: -1 });

module.exports = mongoose.model("AgentHeartbeat", AgentHeartbeatSchema);