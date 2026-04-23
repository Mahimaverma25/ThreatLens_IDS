const mongoose = require("mongoose");

const PlaybookExecutionSchema = new mongoose.Schema(
  {
    _org_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
      required: true,
      index: true,
    },
    alert_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Alert",
      required: true,
      index: true,
    },
    playbook_id: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    playbook_name: {
      type: String,
      required: true,
      trim: true,
    },
    note: {
      type: String,
      trim: true,
      default: "",
    },
    triggered_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    metadata: {
      type: Object,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

PlaybookExecutionSchema.index({ _org_id: 1, createdAt: -1 });

module.exports = mongoose.model("PlaybookExecution", PlaybookExecutionSchema);
