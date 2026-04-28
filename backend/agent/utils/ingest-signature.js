const crypto = require("crypto");

const SIGNATURE_VERSION = "v2";

const sha256 = (value) =>
  crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");

const getPayloadString = (body) => JSON.stringify(body || {});

const buildPayloadHash = (body) => sha256(getPayloadString(body));

const deriveSigningKey = (secret) => sha256(secret);

const buildSignature = ({ apiSecret, timestamp, nonce, assetId, body }) =>
  crypto
    .createHmac("sha256", deriveSigningKey(apiSecret))
    .update(`${timestamp}.${nonce}.${assetId}.${buildPayloadHash(body)}`, "utf8")
    .digest("hex");

module.exports = {
  SIGNATURE_VERSION,
  buildPayloadHash,
  buildSignature,
};
