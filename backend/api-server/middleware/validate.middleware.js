const Organization = require("../models/Organization");

// 🔐 Middleware for API Key Authentication (ONLY for agents/log ingestion)
const validateAPIKey = async (req, res, next) => {
  try {
    const apiKey = req.headers["x-api-key"];
    const assetId = req.headers["x-asset-id"];

    // 🔍 Debug (optional)
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

    // ✅ Attach org info to request
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

module.exports = validateAPIKey;