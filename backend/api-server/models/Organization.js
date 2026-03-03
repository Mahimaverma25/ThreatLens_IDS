const mongoose = require("mongoose");
const crypto = require("crypto");

const OrganizationSchema = new mongoose.Schema(
  {
    // Unique org identifier
    org_id: {
      type: String,
      unique: true,
      required: true,
      immutable: true
    },

    // Organization name
    org_name: {
      type: String,
      required: true,
      trim: true
    },

    // Optional domain
    org_domain: {
      type: String,
      trim: true
    },

    // Plan tier
    org_plan: {
      type: String,
      enum: ["free", "starter", "professional", "enterprise"],
      default: "starter"
    },

    // API quotas
    ingest_quota_per_minute: {
      type: Number,
      default: 1000
    },

    ingest_quota_per_day: {
      type: Number,
      default: 100000000
    },

    // Data retention
    data_retention_days: {
      type: Number,
      default: 30
    },

    // Alert severity threshold
    alert_severity_threshold: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium"
    },

    // Feature flags
    features_enabled: {
      anomaly_detection: { type: Boolean, default: false },
      correlation_engine: { type: Boolean, default: true },
      threat_intel_enrichment: { type: Boolean, default: false },
      custom_rules: { type: Boolean, default: false }
    },

    // Agent API key (for ingest authentication)
    agent_api_key: {
      type: String,
      unique: true,
      sparse: true
    },

    // Organization status
    status: {
      type: String,
      enum: ["active", "suspended", "inactive"],
      default: "active"
    }
  },
  {
    timestamps: true // auto adds createdAt & updatedAt
  }
);

/* ================= PRE-SAVE HOOK ================= */

// Generate API key automatically if not exists
OrganizationSchema.pre("save", function (next) {
  if (!this.agent_api_key) {
    this.agent_api_key = crypto.randomBytes(32).toString("hex");
  }
  next();
});

/* ================= INDEXES ================= */

// Keep indexes ONLY here (not inside fields)
OrganizationSchema.index({ org_id: 1 });
OrganizationSchema.index({ status: 1 });
OrganizationSchema.index({ agent_api_key: 1 });

module.exports = mongoose.model("Organization", OrganizationSchema);