const mongoose = require("mongoose");

const RuleSchema = new mongoose.Schema({
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  name: {
    type: String,
    required: true,
    trim: true
  },

  description: {
    type: String,
    trim: true,
    default: ""
  },

  enabled: {
    type: Boolean,
    default: true,
    index: true
  },

  severity: {
    type: String,
    enum: ["Low", "Medium", "High", "Critical"],
    default: "Medium"
  },

  category: {
    type: String,
    enum: ["network", "host", "auth", "file", "process", "custom"],
    default: "custom"
  },

  conditions: [{
    field: { type: String, required: true },
    operator: {
      type: String,
      enum: ["equals", "not_equals", "contains", "not_contains", "greater_than", "less_than", "regex", "in", "exists"],
      required: true
    },
    value: { type: mongoose.Schema.Types.Mixed, required: true }
  }],

  logic: {
    type: String,
    enum: ["AND", "OR"],
    default: "AND"
  },

  action: {
    type: String,
    enum: ["alert", "log", "block"],
    default: "alert"
  },

  alertType: {
    type: String,
    trim: true,
    default: "Custom Rule Match"
  },

  cooldownMinutes: {
    type: Number,
    default: 10,
    min: 0
  },

  hitCount: {
    type: Number,
    default: 0
  },

  lastTriggered: {
    type: Date,
    default: null
  },

  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  created_at: {
    type: Date,
    default: Date.now,
    immutable: true
  },

  updated_at: {
    type: Date,
    default: Date.now
  }
});

RuleSchema.pre("save", function (next) {
  this.updated_at = Date.now();
  next();
});

RuleSchema.index({ _org_id: 1, enabled: 1 });
RuleSchema.index({ _org_id: 1, category: 1 });

module.exports = mongoose.model("Rule", RuleSchema);
