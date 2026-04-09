const { validationResult } = require("express-validator");
const Organization = require("../models/Organization");

/* =========================
   🔐 REQUEST VALIDATION (FOR AUTH)
========================= */
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array(),
    });
  }

  next();
};

/* =========================
   🔐 API KEY AUTH (FOR AGENT / LOGS)
========================= */
const validateAPIKey = async (req, res, next) => {
  try {
    const apiKey = req.headers["x-api-key"];
    const assetId = req.headers["x-asset-id"];

    console.log("API KEY:", apiKey);
    console.log("ASSET ID:", assetId);

    // ❌ Missing headers
    if (!apiKey || !assetId) {
      return res.status(400).json({
        error: "Missing required headers",
        required: ["x-api-key", "x-asset-id"],
      });
    }

    // 🔍 Find organization
    const org = await Organization.findOne({
      agent_api_key: apiKey,
    });

    if (!org) {
      return res.status(401).json({
        error: "Invalid API key",
      });
    }

    // ❌ Inactive org
    if (org.status !== "active") {
      return res.status(403).json({
        error: "Organization inactive",
      });
    }

    // ✅ Attach org info
    req.org = org;
    req.orgId = org._id;
    req.assetId = assetId;

    next();
  } catch (err) {
    console.error("[API KEY AUTH ERROR]", err);

    return res.status(500).json({
      error: "Authentication error",
    });
  }
};

/* =========================
   EXPORTS
========================= */
module.exports = {
  validateRequest,
  validateAPIKey,
};