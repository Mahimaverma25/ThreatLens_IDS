const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");
const {
  generateAPIKey,
  listAPIKeys,
  getAPIKey,
  revokeAPIKey,
  rotateAPIKey
} = require("../controllers/apikey.controller");

// All API key routes require authentication, org isolation (app level), and admin role
router.use(authenticate, authorizeAdmin);

// List all API keys for organization
router.get("/", asyncHandler(listAPIKeys));

// Get specific API key details
router.get("/:id", asyncHandler(getAPIKey));

// Generate new API key for an asset
router.post("/", asyncHandler(generateAPIKey));

// Revoke API key
router.delete("/:id", asyncHandler(revokeAPIKey));

// Rotate API key (generate new secret)
router.post("/:id/rotate", asyncHandler(rotateAPIKey));

module.exports = router;
