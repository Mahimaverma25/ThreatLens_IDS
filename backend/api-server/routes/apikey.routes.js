const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const {
  generateAPIKey,
  listAPIKeys,
  getAPIKey,
  revokeAPIKey,
  rotateAPIKey
} = require("../controllers/apikey.controller");

// All API key routes require auth + org isolation + admin role
router.use(authenticate, orgIsolation, authorize(["admin"]));

// List all API keys for organization
router.get("/", listAPIKeys);

// Get specific API key details
router.get("/:id", getAPIKey);

// Generate new API key for an asset
router.post("/", generateAPIKey);

// Revoke API key
router.delete("/:id", revokeAPIKey);

// Rotate API key (generate new secret)
router.post("/:id/rotate", rotateAPIKey);

module.exports = router;
