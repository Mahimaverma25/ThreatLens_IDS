const router = require("express").Router();
const multer = require("multer");
const { validateAPIKey, validateIngestPayload } = require("../middleware/ingest.middleware");
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  listLogs,
  createLog,
  ingestLogs,
  uploadLogs,
  simulateTraffic
} = require("../controllers/logs.controller");

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
router.get("/", authenticate, asyncHandler(listLogs));

// Create log manually
router.post("/", authenticate, asyncHandler(createLog));

// Upload logs file
router.post(
  "/upload",
  authenticate,
  authorize(["admin", "analyst"]),
  upload.single("file"),
  asyncHandler(uploadLogs)
);

// Simulate traffic
router.post(
  "/simulate",
  authenticate,
  authorize(["admin", "analyst"]),
  asyncHandler(simulateTraffic)
);

module.exports = router;