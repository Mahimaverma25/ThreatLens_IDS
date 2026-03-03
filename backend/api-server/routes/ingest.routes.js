/**
 * Ingest Routes
 * Endpoints for agent data submission
 * Uses API key authentication (not JWT)
 */

const express = require("express");
const router = express.Router();

const { validateAPIKey, validateIngestPayload } = require("../middleware/ingest.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const IngestController = require("../controllers/ingest.controller");

/**
 * POST /api/ingest/v1/ingest
 * Agent submits events
 * Requires: X-API-Key, X-Timestamp, X-Signature, X-Asset-ID
 */
router.post("/v1/ingest", validateAPIKey, validateIngestPayload, IngestController.ingestEvents);

/**
 * GET /api/ingest/v1/health
 * Health check - no auth required
 */
router.get("/v1/health", IngestController.healthCheck);

/**
 * GET /api/ingest/v1/stats
 * Ingest statistics - requires org context
 * Requires: JWT auth
 */
router.get("/v1/stats", orgIsolation, IngestController.getIngestStats);

module.exports = router;
