const mongoose = require("mongoose");

const incidentNoteSchema = new mongoose.Schema(
  {
    note: {
      type: String,
      required: true,
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
  { _id: false }
);

const incidentSchema = new mongoose.Schema(
  {
    _org_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
      index: true,
    },

    incidentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    title: {
      type: String,
      required: true,
      trim: true,
    },

    attackType: {
      type: String,
      trim: true,
      default: "",
      index: true,
    },

    source: {
      type: String,
      trim: true,
      default: "correlation-engine",
      index: true,
    },

    summary: {
      type: String,
      trim: true,
      default: "",
    },

    severity: {
      type: String,
      enum: ["Critical", "High", "Medium", "Low"],
      default: "Medium",
      index: true,
    },

    status: {
      type: String,
      enum: ["Open", "Acknowledged", "Investigating", "Contained", "Resolved", "False Positive"],
      default: "Open",
      index: true,
    },

    sourceIps: [
      {
        type: String,
        trim: true,
      },
    ],

    destinationIps: [
      {
        type: String,
        trim: true,
      },
    ],

    assetIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Asset",
      },
    ],

    alertIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Alert",
      },
    ],

    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    notes: [incidentNoteSchema],

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

    eventCount: {
      type: Number,
      default: 0,
      min: 0,
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
  },
  { timestamps: true }
);

module.exports = mongoose.model("Incident", incidentSchema);
