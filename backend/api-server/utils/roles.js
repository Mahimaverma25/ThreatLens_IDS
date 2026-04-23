const ROLE_ADMIN = "admin";
const ROLE_ANALYST = "analyst";
const ROLE_VIEWER = "viewer";

const LEGACY_VIEWER_ROLES = new Set(["user", ROLE_VIEWER]);

const normalizeRole = (role) => {
  if (role === ROLE_ADMIN) {
    return ROLE_ADMIN;
  }

  if (role === ROLE_ANALYST) {
    return ROLE_ANALYST;
  }

  if (LEGACY_VIEWER_ROLES.has(role)) {
    return ROLE_VIEWER;
  }

  return ROLE_VIEWER;
};

const isAdminRole = (role) => normalizeRole(role) === ROLE_ADMIN;
const isAnalystOrAbove = (role) => [ROLE_ADMIN, ROLE_ANALYST].includes(normalizeRole(role));

module.exports = {
  ROLE_ADMIN,
  ROLE_ANALYST,
  ROLE_VIEWER,
  normalizeRole,
  isAdminRole,
  isAnalystOrAbove,
};
