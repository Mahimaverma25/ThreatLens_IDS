const router = require("express").Router();
const multer = require("multer");

const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");

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
 * orgIsolation is already applied in server.js
 * DO NOT add authenticate here
 */
router.post("/ingest", ingestLogs);

/**
 * ==============================
 * 👤 USER ROUTES (JWT BASED)
 * ==============================
 */

// Get logs
router.get("/", authenticate, listLogs);

// Create log manually
router.post("/", authenticate, createLog);

// Upload logs file
router.post(
  "/upload",
  authenticate,
  authorize(["admin", "analyst"]),
  upload.single("file"),
  uploadLogs
);

// Simulate traffic
router.post(
  "/simulate",
  authenticate,
  authorize(["admin", "analyst"]),
  simulateTraffic
);

module.exports = router;