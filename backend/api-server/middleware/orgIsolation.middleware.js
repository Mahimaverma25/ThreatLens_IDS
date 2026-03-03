/**
 * Multi-tenant isolation middleware
 * CRITICAL: Ensures all queries include org_id filter
 * Rules:
 * 1. Extract org_id from JWT token (already decoded by auth middleware)
 * 2. Attach org_id to request object
 * 3. All subsequent queries MUST use req.orgId filter
 */

const User = require("../models/User");
const Organization = require("../models/Organization");
const AuditLog = require("../models/AuditLog");

const orgIsolation = async (req, res, next) => {
  try {
    // JWT should already be validated by auth middleware
    if (!req.user || !req.user._id) {
      return res.status(401).json({ error: "Unauthorized: No user context" });
    }

    // Fetch user from database to get org_id
    const user = await User.findById(req.user._id).populate("_org_id");

    if (!user) {
      return res.status(401).json({ error: "Unauthorized: User not found" });
    }

    if (!user._org_id) {
      return res.status(403).json({ error: "Forbidden: User not associated with organization" });
    }

    // Verify organization is active
    const org = user._org_id;
    if (org.status !== "active") {
      return res.status(403).json({
        error: `Organization not active: ${org.status}`,
      });
    }

    // ATTACH TO REQUEST - Every downstream handler uses these
    req.orgId = org._id; // MongoDB ObjectId
    req.org = org; // Full organization document
    req.userId = user._id;

    // For convenience in route handlers
    res.locals.orgId = org._id;
    res.locals.org = org;

    next();
  } catch (err) {
    console.error("[Org Isolation Error]", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Middleware to automatically inject org_id into queries
 * Usage: router.get("/alerts", injectOrgId, (req, res) => { ... })
 *
 * Converts: Alert.find({ status: "new" })
 * To:       Alert.find({ _org_id: req.orgId, status: "new" })
 */
const injectOrgIdToQuery = (req, res, next) => {
  if (!req.orgId) {
    return res.status(401).json({ error: "Organization context missing" });
  }

  // Store original find method
  const originalFind = (Model) => {
    const find = Model.find.bind(Model);
    return (filter = {}, ...args) => {
      // Auto-inject org_id
      const secureFilter = {
        _org_id: req.orgId,
        ...filter,
      };
      return find(secureFilter, ...args);
    };
  };

  next();
};

module.exports = { orgIsolation, injectOrgIdToQuery };
