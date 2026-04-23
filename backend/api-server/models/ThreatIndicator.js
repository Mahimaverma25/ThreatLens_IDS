const mongoose = require("mongoose");

const ThreatIndicatorSchema = new mongoose.Schema(
  {
    _org_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
      required: true,
      index: true,
    },
    indicator_type: {
      type: String,
      enum: ["ip", "domain", "hash", "note"],
      default: "ip",
      index: true,
    },
    value: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    confidence: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium",
    },
    source: {
      type: String,
      trim: true,
      default: "analyst-watchlist",
    },
    status: {
      type: String,
      enum: ["active", "inactive"],
      default: "active",
      index: true,
    },
    notes: {
      type: String,
      trim: true,
      default: "",
    },
    created_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

ThreatIndicatorSchema.index({ _org_id: 1, value: 1 }, { unique: true });

module.exports = mongoose.model("ThreatIndicator", ThreatIndicatorSchema);
