const express = require("express");
const router = express.Router();

/**
 * ==============================
 * ✅ HEALTH CHECK
 * ==============================
 */
router.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

/**
 * ==============================
 * 🚫 REMOVE THIS FILE LOGIC
 * ==============================
 * Ingest is now handled by:
 * /api/logs/ingest
 *
 * Using:
 * - x-api-key
 * - x-org-id
 * - orgIsolation middleware
 */

/**
 * OPTIONAL: Redirect old endpoint to new one
 */
router.post("/v1/ingest", (req, res) => {
  res.status(410).json({
    error: "Deprecated endpoint",
    message: "Use /api/logs/ingest instead"
  });
});

module.exports = router;