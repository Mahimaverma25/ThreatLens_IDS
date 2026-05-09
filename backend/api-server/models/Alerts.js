const mongoose = require("mongoose");

const AlertSchema = new mongoose.Schema(
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
      index: true,
    },

    _incident_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Incident",
      index: true,
    },

    alertId: {
      type: String,
      required: true,
      index: true,
      trim: true,
    },

    type: {
      type: String,
      required: true,
      trim: true,
    },

    attackType: {
      type: String,
      required: true,
      trim: true,
    },

    ip: {
      type: String,
      required: true,
      trim: true,
      index: true,
      default: "unknown",
    },

    severity: {
      type: String,
      required: true,
      enum: ["Low", "Medium", "High", "Critical"],
      default: "Medium",
      trim: true,
      index: true,
    },

    status: {
      type: String,
      enum: [
        "New",
        "Acknowledged",
        "Investigating",
        "Resolved",
        "False Positive",
      ],
      default: "New",
      index: true,
    },

    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },

    risk_score: {
      type: Number,
      min: 0,
      max: 100,
      default: 50,
      index: true,
    },

    recommendedAction: {
      type: String,
      trim: true,
      default: "",
    },

    analystNotes: [
      {
        note: {
          type: String,
          trim: true,
        },
        by: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        timestamp: {
          type: Date,
          default: Date.now,
        },
      },
    ],

    resolvedAt: Date,

    relatedLogs: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Log",
      },
    ],

    source: {
      type: String,
      default: "ids-engine",
      trim: true,
      index: true,
    },

    metadata: {
      type: Object,
      default: {},
    },

    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: {
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
  }
);

AlertSchema.index({ _org_id: 1, timestamp: -1 });
AlertSchema.index({ _org_id: 1, status: 1, severity: -1 });
AlertSchema.index({ _org_id: 1, _incident_id: 1 });
AlertSchema.index({ _org_id: 1, ip: 1 });
AlertSchema.index({ _org_id: 1, type: 1, ip: 1, timestamp: -1 });
AlertSchema.index({ _org_id: 1, attackType: 1, timestamp: -1 });
AlertSchema.index({ _org_id: 1, risk_score: -1 });

module.exports = mongoose.model("Alert", AlertSchema);