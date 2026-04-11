const router = require("express").Router();
const multer = require("multer");
const { validateAPIKey, validateIngestPayload } = require("../middleware/ingest.middleware");
const authenticate = require("../middleware/auth.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const authorize = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  listLogs,
  createLog,
  ingestLogs,
  uploadLogs,
  simulateTraffic
} = require("../controllers/log.controller");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }
});

/**
 * ==============================
 * 🤖 AGENT ROUTE (API KEY BASED)
 * ==============================
 * Validates API key with HMAC signature
 * Validates payload structure
 * Routes to org isolation context
 */
router.post(
  "/ingest",
  validateAPIKey,
  validateIngestPayload,
  asyncHandler(ingestLogs)
);

/**
 * ==============================
 * 👤 USER ROUTES (JWT BASED)
 * ==============================
 */

// Get logs
router.get("/", authenticate, orgIsolation, asyncHandler(listLogs));

// Create log manually
router.post("/", authenticate, orgIsolation, asyncHandler(createLog));

// Upload logs file
router.post(
  "/upload",
  authenticate,
  orgIsolation,
  authorize(["admin", "analyst"]),
  upload.single("file"),
  asyncHandler(uploadLogs)
);

// Simulate traffic
router.post(
  "/simulate",
  authenticate,
  orgIsolation,
  authorize(["admin", "analyst"]),
  asyncHandler(simulateTraffic)
);

module.exports = router;