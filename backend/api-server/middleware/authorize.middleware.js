const Log = require("../models/Log");

const authorize = (roles = []) => async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  if (roles.length > 0 && !roles.includes(req.user.role)) {
    try {
      if (req.orgId) {
        await Log.create({
          _org_id: req.orgId,
          message: "Unauthorized role access",
          level: "warn",
          source: "authz",
          ip: req.ip,
          userId: req.user.sub,
          eventType: "authz.denied",
          metadata: { requiredRoles: roles, role: req.user.role, path: req.originalUrl }
        });
      }
    } catch (error) {
      console.error("[Authorize Log Error]", error);
    }

    return res.status(403).json({ message: "Forbidden" });
  }

  return next();
};

module.exports = authorize;
