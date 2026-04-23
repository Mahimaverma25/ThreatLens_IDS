const mongoose = require("mongoose");

const IncidentSchema = new mongoose.Schema({
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  incidentId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  title: {
    type: String,
    required: true,
    trim: true
  },

  description: {
    type: String,
    trim: true,
    default: ""
  },

  severity: {
    type: String,
    enum: ["Low", "Medium", "High", "Critical"],
    required: true,
    index: true
  },

  status: {
    type: String,
    enum: ["Open", "Investigating", "Resolved", "Closed"],
    default: "Open",
    index: true
  },

  assignee: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },

  alerts: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Alert"
  }],

  affectedAssets: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Asset"
  }],

  sourceIps: [{ type: String }],

  attackTypes: [{ type: String }],

  timeline: [{
    action: { type: String, required: true },
    details: { type: String, default: "" },
    by: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    automatic: { type: Boolean, default: false },
    timestamp: { type: Date, default: Date.now }
  }],

  metadata: {
    type: Object,
    default: {}
  },

  created_at: {
    type: Date,
    default: Date.now,
    immutable: true,
    index: true
  },

  updated_at: {
    type: Date,
    default: Date.now
  },

  resolved_at: {
    type: Date,
    default: null
  }
});

IncidentSchema.pre("save", function (next) {
  this.updated_at = Date.now();
  next();
});

IncidentSchema.index({ _org_id: 1, created_at: -1 });
IncidentSchema.index({ _org_id: 1, status: 1, severity: 1 });
IncidentSchema.index({ _org_id: 1, assignee: 1 });

module.exports = mongoose.model("Incident", IncidentSchema);
