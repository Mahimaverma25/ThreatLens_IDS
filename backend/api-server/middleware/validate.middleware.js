const Organization = require("../models/Organization");

const validateAPIKey = async (req, res, next) => {
  try {
    const apiKey = req.header("X-API-Key");
    const assetId = req.header("X-Asset-ID");

    if (!apiKey || !assetId) {
      return res.status(400).json({
        error: "Missing required headers",
        required: ["X-API-Key", "X-Asset-ID"],
      });
    }

    const org = await Organization.findOne({
      agent_api_key: apiKey,
      status: "active",
    });

    if (!org) {
      return res.status(401).json({
        error: "Invalid API key",
      });
    }

    req.org = org;
    req.orgId = org._id;
    req.assetId = assetId;

    next();
  } catch (err) {
    console.error("[Auth Error]", err);
    res.status(500).json({ error: "Authentication error" });
  }
};

module.exports = validateAPIKey;