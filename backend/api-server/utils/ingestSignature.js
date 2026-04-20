const crypto = require("crypto");

const SIGNATURE_VERSION = "v2";

const sha256 = (value) =>
  crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");

const getPayloadString = (body, rawBody = "") => {
  if (typeof rawBody === "string" && rawBody.length > 0) {
    return rawBody;
  }

  return JSON.stringify(body || {});
};

const buildPayloadHash = (body, rawBody = "") => sha256(getPayloadString(body, rawBody));

const deriveSigningKey = (secret) => sha256(secret);

const buildSigningContent = ({ timestamp, assetId, payloadHash }) =>
  `${timestamp}.${assetId}.${payloadHash}`;

const buildSignatureFromSigningKey = ({ signingKey, timestamp, assetId, payloadHash }) =>
  crypto
    .createHmac("sha256", signingKey)
    .update(buildSigningContent({ timestamp, assetId, payloadHash }), "utf8")
    .digest("hex");

const buildSignature = ({ apiSecret, timestamp, assetId, body, rawBody = "" }) =>
  buildSignatureFromSigningKey({
    signingKey: deriveSigningKey(apiSecret),
    timestamp,
    assetId,
    payloadHash: buildPayloadHash(body, rawBody),
  });

const buildLegacySignature = ({ apiSecret, timestamp, body, rawBody = "" }) =>
  crypto
    .createHmac("sha256", apiSecret)
    .update(`${timestamp}.${getPayloadString(body, rawBody)}`, "utf8")
    .digest("hex");

module.exports = {
  SIGNATURE_VERSION,
  sha256,
  getPayloadString,
  buildPayloadHash,
  deriveSigningKey,
  buildSignatureFromSigningKey,
  buildSignature,
  buildLegacySignature,
};
