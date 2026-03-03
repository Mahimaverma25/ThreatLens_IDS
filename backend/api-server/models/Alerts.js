const mongoose = require("mongoose");

const AlertSchema = new mongoose.Schema({
  // Multi-tenant field - CRITICAL
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  // Asset this alert is about
  _asset_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Asset",
    index: true
  },

  // Incident this belongs to (after correlation)
  _incident_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Incident"
  },

  alertId: { type: String, required: true, index: true },
  type: { type: String, required: true, trim: true },
  attackType: { type: String, required: true, trim: true },
  ip: { type: String, required: true, trim: true, index: true },
  severity: {
    type: String,
    required: true,
    enum: ["Low", "Medium", "High", "Critical"],
    trim: true,
    index: true
  },
  status: {
    type: String,
    enum: ["New", "Acknowledged", "Investigating", "Resolved", "False Positive"],
    default: "New",
    index: true
  },
  confidence: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.5
  },
  risk_score: {
    type: Number,
    min: 0,
    max: 100,
    default: 50
  },
  analystNotes: [
    {
      note: { type: String, trim: true },
      by: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      timestamp: { type: Date, default: Date.now }
    }
  ],
  resolvedAt: { type: Date },
  relatedLogs: [{ type: mongoose.Schema.Types.ObjectId, ref: "Log" }],
  source: { type: String, default: "ids-engine", trim: true },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

// Indexes for multi-tenant queries
AlertSchema.index({ _org_id: 1, created_at: -1 });
AlertSchema.index({ _org_id: 1, status: 1, severity: -1 });
AlertSchema.index({ _org_id: 1, _incident_id: 1 });
AlertSchema.index({ _org_id: 1, ip: 1 });

module.exports = mongoose.model("Alert", AlertSchema);
