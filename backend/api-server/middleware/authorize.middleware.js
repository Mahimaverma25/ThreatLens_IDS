const Log = require("../models/Log");
const { ROLE_ADMIN, ROLE_VIEWER, normalizeRole } = require("../utils/roles");

const authorize = (roles = []) => async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const normalizedRole = normalizeRole(req.user.role);
  req.user.role = normalizedRole;

  if (roles.length > 0 && !roles.includes(normalizedRole)) {
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
          metadata: { requiredRoles: roles, role: normalizedRole, path: req.originalUrl }
        });
      }
    } catch (error) {
      console.error("[Authorize Log Error]", error);
    }

    return res.status(403).json({ message: "Forbidden" });
  }

  return next();
};

const authorizeAdmin = authorize([ROLE_ADMIN]);
const authorizeViewer = authorize([ROLE_ADMIN, ROLE_VIEWER]);

module.exports = authorize;
module.exports.authorizeAdmin = authorizeAdmin;
module.exports.authorizeViewer = authorizeViewer;
