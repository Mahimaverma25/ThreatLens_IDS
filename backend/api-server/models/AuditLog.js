const mongoose = require("mongoose");

const AuditLogSchema = new mongoose.Schema(
  {
    // Multi-tenant field
    // Optional because failed login attempts may not have org context
    _org_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
      required: false,
      index: true,
      default: null
    },

    action: {
      type: String,
      required: true,
      trim: true,
      index: true
    },

    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },

    ip: {
      type: String,
      trim: true
    },

    userAgent: {
      type: String,
      trim: true
    },

    success: {
      type: Boolean,
      default: false,
      index: true
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  {
    timestamps: true // automatically adds createdAt & updatedAt
  }
);

/* ================= INDEXES ================= */

// Multi-tenant queries
AuditLogSchema.index({ _org_id: 1, createdAt: -1 });

// User activity tracking
AuditLogSchema.index({ _org_id: 1, userId: 1, createdAt: -1 });

// Security analysis
AuditLogSchema.index({ action: 1, success: 1, createdAt: -1 });

module.exports = mongoose.model("AuditLog", AuditLogSchema);