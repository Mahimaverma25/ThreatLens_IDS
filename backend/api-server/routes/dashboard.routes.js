const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const asyncHandler = require("../utils/asyncHandler");
const { getStats, getHealth } = require("../controllers/dashboard.controller");

// All dashboard routes require authentication and org isolation
router.get("/stats", authenticate, asyncHandler(getStats));
router.get("/health", authenticate, asyncHandler(getHealth));

module.exports = router;
