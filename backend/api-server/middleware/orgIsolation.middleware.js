const Organization = require("../models/Organization");
const User = require("../models/User");

const ensureActiveOrganization = (org, res) => {
  if (!org) {
    res.status(404).json({ message: "Organization not found" });
    return false;
  }

  if (org.status && org.status !== "active") {
    res.status(403).json({ message: `Organization not active: ${org.status}` });
    return false;
  }

  return true;
};

const orgIsolation = async (req, res, next) => {
  try {
    // Upstream agent/auth middleware may already attach trusted organization context.
    if (req.orgId) {
      if (req.org) {
        if (!ensureActiveOrganization(req.org, res)) {
          return;
        }
        res.locals.orgId = req.orgId;
        res.locals.org = req.org;
        return next();
      }

      const trustedOrg = await Organization.findById(req.orgId);
      if (!ensureActiveOrganization(trustedOrg, res)) {
        return;
      }

      req.org = trustedOrg;
      res.locals.orgId = trustedOrg._id;
      res.locals.org = trustedOrg;
      return next();
    }

    const userId = req.user?._id || req.user?.sub;
    if (!req.user || !userId) {
      return res.status(401).json({ message: "Unauthorized: no user context" });
    }

    const user = await User.findById(userId).populate("_org_id");
    if (!user) {
      return res.status(401).json({ message: "Unauthorized: user not found" });
    }

    if (!user._org_id) {
      return res.status(403).json({
        message: "Forbidden: user is not associated with an organization",
      });
    }

    const org = user._org_id;
    if (!ensureActiveOrganization(org, res)) {
      return;
    }

    req.orgId = org._id;
    req.org = org;
    req.userId = user._id;
    res.locals.orgId = org._id;
    res.locals.org = org;

    return next();
  } catch (error) {
    console.error("[Org Isolation Error]", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

module.exports = { orgIsolation };
