const ROLE_ADMIN = "admin";
const ROLE_VIEWER = "viewer";

const LEGACY_VIEWER_ROLES = new Set(["user", "analyst", ROLE_VIEWER]);

const normalizeRole = (role) => {
  if (role === ROLE_ADMIN) {
    return ROLE_ADMIN;
  }

  if (LEGACY_VIEWER_ROLES.has(role)) {
    return ROLE_VIEWER;
  }

  return ROLE_VIEWER;
};

const isAdminRole = (role) => normalizeRole(role) === ROLE_ADMIN;

module.exports = {
  ROLE_ADMIN,
  ROLE_VIEWER,
  normalizeRole,
  isAdminRole,
};
