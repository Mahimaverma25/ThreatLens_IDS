/**
 * 🚀 ThreatLens Ingestion Middleware (UPDATED)
 */
const crypto = require("crypto");

/* ================= API KEY VALIDATION ================= */

const validateAPIKey = async (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  const orgId = req.headers["x-org-id"];

  const SECRET = "tlk_secret_dev_123456";
  console.log("EXPECTED SECRET:", SECRET);
  console.log("RECEIVED KEY:", req.headers["x-api-key"]);

  // ✅ SIMPLE AUTH (CURRENT SYSTEM)
  if (!apiKey || apiKey !== SECRET) {
    console.warn("[Auth] Invalid API Key:", apiKey);
    return res.status(401).json({
      error: "Invalid API Key or Org ID",
    });
  }

  // ✅ Attach context from headers (REAL DATA)
  req.orgId = orgId || "default-org";
  req.assetId = req.headers["x-asset-id"] || "unknown-asset";

  next();
};

/* ================= PAYLOAD VALIDATION ================= */

const validateIngestPayload = (req, res, next) => {
  const { logs } = req.body;

  // ✅ Check logs array
  if (!logs || !Array.isArray(logs)) {
    return res.status(400).json({
      error: "Invalid payload",
      message: "logs array is required",
    });
  }

  // ✅ Validate each log
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];

    if (!log.message || !log.level || !log.timestamp) {
      return res.status(400).json({
        error: "Invalid log format",
        index: i,
        required: ["message", "level", "timestamp"],
      });
    }
  }

  next();
};

module.exports = {
  validateAPIKey,
  validateIngestPayload,
};
