const Organization = require("../models/Organization");

const validateAPIKey = async (req, res, next) => {
  try {
    const apiKey = req.headers["x-api-key"];
    const assetId = req.headers["x-asset-id"];

    if (!apiKey || !assetId) {
      return res.status(400).json({
        error: "Missing required headers"
      });
    }

    const org = await Organization.findOne({
      agent_api_key: apiKey
    });

    if (!org) {
      return res.status(401).json({
        error: "Invalid API key"
      });
    }

    req.org = org;
    req.assetId = assetId;

    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Auth error" });
  }
};

module.exports = validateAPIKey; 