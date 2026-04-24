const router = require("express").Router();

const authenticate = require("../middleware/auth.middleware");
const { authorizeViewer } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  getStats,
  getHealth,
  getOverview,
} = require("../controllers/dashboard.controller");

// Dashboard routes require login + viewer/admin/analyst access
router.get("/stats", authenticate, authorizeViewer, asyncHandler(getStats));
router.get("/health", authenticate, authorizeViewer, asyncHandler(getHealth));
router.get("/overview", authenticate, authorizeViewer, asyncHandler(getOverview));

module.exports = router;