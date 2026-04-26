const mongoose = require("mongoose");

const IngestNonceSchema = new mongoose.Schema(
  {
    nonce: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
    },
    apiKeyToken: {
      type: String,
      required: true,
      index: true,
      trim: true,
    },
    assetIdentifier: {
      type: String,
      required: true,
      trim: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },
    },
  },
  {
    timestamps: {
      createdAt: "createdAt",
      updatedAt: false,
    },
    versionKey: false,
  }
);

module.exports = mongoose.model("IngestNonce", IngestNonceSchema);
