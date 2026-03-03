const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const { getStats, getHealth } = require("../controllers/dashboard.controller");

// All dashboard routes require org isolation
router.get("/stats", authenticate, orgIsolation, getStats);
router.get("/health", authenticate, orgIsolation, getHealth);

module.exports = router;
