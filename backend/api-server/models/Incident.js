const mongoose = require("mongoose");

const IncidentNoteSchema = new mongoose.Schema(
  {
    note: {
      type: String,
      required: true,
      trim: true,
    },
    by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false }
);

const IncidentTimelineSchema = new mongoose.Schema(
  {
    action: { type: String, required: true, trim: true },
    details: { type: String, default: "", trim: true },
    by: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    automatic: { type: Boolean, default: false },
    timestamp: { type: Date, default: Date.now },
  },
  { _id: false }
);

const IncidentSchema = new mongoose.Schema({
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true,
  },

  incidentId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    trim: true,
  },

  title: {
    type: String,
    required: true,
    trim: true,
  },

  description: {
    type: String,
    trim: true,
    default: "",
  },

  summary: {
    type: String,
    trim: true,
    default: "",
  },

  severity: {
    type: String,
    enum: ["Low", "Medium", "High", "Critical"],
    required: true,
    index: true,
  },

  status: {
    type: String,
    enum: [
      "Open",
      "Acknowledged",
      "Investigating",
      "Contained",
      "Resolved",
      "False Positive",
      "Closed",
    ],
    default: "Open",
    index: true,
  },

  attackType: {
    type: String,
    trim: true,
    default: "",
    index: true,
  },

  attackTypes: [{ type: String, trim: true }],

  source: {
    type: String,
    trim: true,
    default: "correlation-engine",
    index: true,
  },

  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },

  assignee: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },

  alertIds: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Alert",
    },
  ],

  alerts: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Alert",
    },
  ],

  assetIds: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Asset",
    },
  ],

  affectedAssets: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Asset",
    },
  ],

  sourceIps: [{ type: String, trim: true }],
  destinationIps: [{ type: String, trim: true }],
  hostnames: [{ type: String, trim: true }],
  userNames: [{ type: String, trim: true }],
  attackChain: [{ type: String, trim: true }],

  confidence: {
    type: Number,
    default: 0.5,
    min: 0,
    max: 1,
  },

  risk_score: {
    type: Number,
    default: 50,
    min: 0,
  },

  eventCount: {
    type: Number,
    default: 0,
    min: 0,
  },

  tags: [{ type: String, trim: true }],

  notes: {
    type: [IncidentNoteSchema],
    default: [],
  },

  timeline: {
    type: [IncidentTimelineSchema],
    default: [],
  },

  metadata: {
    type: Object,
    default: {},
  },

  firstSeen: {
    type: Date,
    default: Date.now,
  },

  lastSeen: {
    type: Date,
    default: Date.now,
    index: true,
  },

  created_at: {
    type: Date,
    default: Date.now,
    immutable: true,
    index: true,
  },

  updated_at: {
    type: Date,
    default: Date.now,
  },

  resolvedAt: {
    type: Date,
    default: null,
  },

  resolved_at: {
    type: Date,
    default: null,
  },
});

IncidentSchema.pre("save", function (next) {
  this.updated_at = Date.now();

  if (!this.owner && this.assignee) {
    this.owner = this.assignee;
  }
  if (!this.assignee && this.owner) {
    this.assignee = this.owner;
  }

  if ((!this.alertIds || this.alertIds.length === 0) && this.alerts?.length) {
    this.alertIds = this.alerts;
  }
  if ((!this.alerts || this.alerts.length === 0) && this.alertIds?.length) {
    this.alerts = this.alertIds;
  }

  if ((!this.assetIds || this.assetIds.length === 0) && this.affectedAssets?.length) {
    this.assetIds = this.affectedAssets;
  }
  if ((!this.affectedAssets || this.affectedAssets.length === 0) && this.assetIds?.length) {
    this.affectedAssets = this.assetIds;
  }

  if (!this.attackType && this.attackTypes?.length) {
    this.attackType = this.attackTypes[0];
  }
  if ((!this.attackTypes || this.attackTypes.length === 0) && this.attackType) {
    this.attackTypes = [this.attackType];
  }

  if ((!this.notes || this.notes.length === 0) && this.timeline?.length) {
    this.notes = this.timeline.map((entry) => ({
      note: entry.details || entry.action,
      by: entry.by || null,
      timestamp: entry.timestamp || new Date(),
    }));
  }

  if (!this.firstSeen) {
    this.firstSeen = this.created_at || new Date();
  }
  if (!this.lastSeen) {
    this.lastSeen = this.updated_at || new Date();
  }

  if (!this.eventCount) {
    this.eventCount = this.alertIds?.length || this.alerts?.length || 0;
  }

  if (!this.resolvedAt && this.resolved_at) {
    this.resolvedAt = this.resolved_at;
  }
  if (!this.resolved_at && this.resolvedAt) {
    this.resolved_at = this.resolvedAt;
  }

  if ((!this.userNames || this.userNames.length === 0) && Array.isArray(this.metadata?.userNames)) {
    this.userNames = this.metadata.userNames;
  }

  if ((!this.attackChain || this.attackChain.length === 0) && Array.isArray(this.metadata?.attackChain)) {
    this.attackChain = this.metadata.attackChain;
  }

  next();
});

IncidentSchema.index({ _org_id: 1, created_at: -1 });
IncidentSchema.index({ _org_id: 1, status: 1, severity: 1 });
IncidentSchema.index({ _org_id: 1, owner: 1 });
IncidentSchema.index({ _org_id: 1, attackType: 1, source: 1, lastSeen: -1 });
IncidentSchema.index({ _org_id: 1, sourceIps: 1, destinationIps: 1, lastSeen: -1 });

module.exports = mongoose.model("Incident", IncidentSchema);
