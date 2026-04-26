const IngestNonce = require("../models/IngestNonce");

const reserveNonce = async ({ nonce, apiKeyToken, assetIdentifier, ttlMs }) => {
  const expiresAt = new Date(Date.now() + ttlMs);

  try {
    await IngestNonce.create({
      nonce,
      apiKeyToken,
      assetIdentifier,
      expiresAt,
    });
    return true;
  } catch (error) {
    if (error?.code === 11000) {
      return false;
    }
    throw error;
  }
};

module.exports = {
  reserveNonce,
};
