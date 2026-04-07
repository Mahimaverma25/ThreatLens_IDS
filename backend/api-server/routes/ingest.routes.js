/**
 * ⚠️ DEPRECATED - This file is no longer in use and should be deleted
 *
 * Ingest API is now handled by:
 * - Route: POST /api/logs/ingest
 * - Middleware: validateAPIKey + validateIngestPayload (from ingest.middleware.js)
 *
 * To use the ingest endpoint:
 * - Endpoint: POST /api/logs/ingest
 * - Headers: X-API-Key, X-Timestamp, X-Signature, X-Asset-ID
 * - Body: { events: [...] }
 *
 * See: backend/api-server/routes/logs.routes.js
 */

const express = require("express");
const router = express.Router();

// This router is deprecated and should be removed from imports
module.exports = router;

module.exports = router;