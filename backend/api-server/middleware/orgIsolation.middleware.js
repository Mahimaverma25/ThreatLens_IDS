const User = require("../models/User");
const Organization = require("../models/Organization");

const orgIsolation = async (req, res, next) => {
  try {
    // =========================
    // 🔐 1. AGENT AUTH (API KEY)
    // =========================
    const apiKey = req.headers["x-api-key"];
    const orgIdHeader = req.headers["x-org-id"];

    if (apiKey && orgIdHeader) {
      const org = await Organization.findOne({
        _id: orgIdHeader,
        agent_api_key: apiKey
      });

      if (!org) {
        return res.status(401).json({ error: "Invalid API Key or Org ID" });
      }

      if (org.status && org.status !== "active") {
        return res.status(403).json({
          error: `Organization not active: ${org.status}`
        });
      }

      // Attach org context
      req.orgId = org._id;
      req.org = org;

      return next(); // ✅ agent request allowed
    }

    // =========================
    // 👤 2. USER AUTH (JWT)
    // =========================
    if (!req.user || !req.user._id) {
      return res.status(401).json({ error: "Unauthorized: No user context" });
    }

    const user = await User.findById(req.user._id).populate("_org_id");

    if (!user) {
      return res.status(401).json({ error: "Unauthorized: User not found" });
    }

    if (!user._org_id) {
      return res.status(403).json({
        error: "Forbidden: User not associated with organization"
      });
    }

    const org = user._org_id;

    if (org.status && org.status !== "active") {
      return res.status(403).json({
        error: `Organization not active: ${org.status}`
      });
    }

    req.orgId = org._id;
    req.org = org;
    req.userId = user._id;

    res.locals.orgId = org._id;
    res.locals.org = org;

    next();

  } catch (err) {
    console.error("[Org Isolation Error]", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

module.exports = { orgIsolation };