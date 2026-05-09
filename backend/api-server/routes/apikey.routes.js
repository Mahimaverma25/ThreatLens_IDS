const router = require("express").Router();

const { authorizeAdmin } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  generateAPIKey,
  listAPIKeys,
  getAPIKey,
  revokeAPIKey,
  rotateAPIKey,
} = require("../controllers/apikey.controller");

/**
 * Base route:
 * /api/admin/api-keys
 *
 * Important:
 * authenticate + orgIsolation are already applied in server.js:
 *
 * app.use(
 *   "/api/admin/api-keys",
 *   authenticate,
 *   orgIsolation,
 *   apikeyRoutes
 * );
 *
 * So do not repeat authenticate here.
 */

router.use(authorizeAdmin);

/**
 * GET /api/admin/api-keys
 * List all API keys for the current organization.
 */
router.get("/", asyncHandler(listAPIKeys));

/**
 * POST /api/admin/api-keys
 * Generate a new API key for an asset.
 *
 * Body:
 * {
 *   "asset_id": "...",
 *   "key_name": "Production Agent Key",
 *   "expiration_days": 365
 * }
 */
router.post("/", asyncHandler(generateAPIKey));

/**
 * GET /api/admin/api-keys/:id
 * Get one API key detail without exposing secret hash.
 */
router.get("/:id", asyncHandler(getAPIKey));

/**
 * DELETE /api/admin/api-keys/:id
 * Revoke API key.
 */
router.delete("/:id", asyncHandler(revokeAPIKey));

/**
 * POST /api/admin/api-keys/:id/rotate
 * Rotate API key secret.
 *
 * Body:
 * {
 *   "expiration_days": 365
 * }
 */
router.post("/:id/rotate", asyncHandler(rotateAPIKey));

module.exports = router;