const mongoose = require("mongoose");

const AssetSchema = new mongoose.Schema({
  // Multi-tenant field - CRITICAL
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  // Asset identifier (user-friendly)
  asset_id: {
    type: String,
    required: true,
    trim: true
  },

  // Display name
  asset_name: {
    type: String,
    required: true,
    trim: true
  },

  // Type of asset
  asset_type: {
    type: String,
    enum: ["agent", "web_server", "api_server", "database", "load_balancer", "firewall", "other"],
    default: "web_server"
  },

  // Environment
  asset_environment: {
    type: String,
    enum: ["production", "staging", "development", "lab"],
    default: "production"
  },

  // Criticality for risk scoring
  asset_criticality: {
    type: String,
    enum: ["low", "medium", "high", "critical"],
    default: "medium"
  },

  // Network info
  hostname: String,
  ip_address: String,
  ip_ranges: [String], // CIDR notation

  // Geo information
  geo_region: String,
  geo_country: String,

  // Agent status
  host_platform: String,
  telemetry_types: [String],
  agent_version: String,
  agent_last_seen: Date,
  agent_status: {
    type: String,
    enum: ["online", "offline", "error"],
    default: "offline"
  },

  // Baseline for anomaly detection (will populate after data collection)
  baseline: {
    avg_requests_per_minute: Number,
    avg_errors_per_minute: Number,
    typical_users: [String],
    typical_geographies: [String],
    working_hours: {
      days: [String],
      start_hour: Number,
      end_hour: Number,
      timezone: String
    }
  },

  // Suppression rules (ignore certain alerts)
  suppression_rules: [
    {
      rule_type: String, // 'ip', 'path', 'user', 'status_code'
      condition: String,
      reason: String
    }
  ],

  // Status
  status: {
    type: String,
    enum: ["active", "maintenance", "retiring"],
    default: "active"
  },

  // Timestamps
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

// Update timestamp
AssetSchema.pre("save", function(next) {
  this.updated_at = Date.now();
  next();
});

// CRITICAL: Indexes for multi-tenant queries
AssetSchema.index({ _org_id: 1, asset_id: 1 }, { unique: true });
AssetSchema.index({ _org_id: 1, agent_status: 1 });
AssetSchema.index({ _org_id: 1, status: 1 });

module.exports = mongoose.model("Asset", AssetSchema);
