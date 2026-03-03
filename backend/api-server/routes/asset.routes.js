const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const {
  createAsset,
  listAssets,
  getAsset,
  updateAsset,
  deleteAsset,
  addSuppressionRule,
  removeSuppressionRule
} = require("../controllers/asset.controller");

// All asset routes require auth + org isolation
router.use(authenticate, orgIsolation);

// List assets
router.get("/", listAssets);

// Get asset details
router.get("/:id", getAsset);

// Create asset (admin only)
router.post("/", authorize(["admin"]), createAsset);

// Update asset (admin only)
router.patch("/:id", authorize(["admin"]), updateAsset);

// Delete asset (admin only)
router.delete("/:id", authorize(["admin"]), deleteAsset);

// Add suppression rule (admin only)
router.post("/:id/suppression-rules", authorize(["admin"]), addSuppressionRule);

// Remove suppression rule (admin only)
router.delete("/:id/suppression-rules/:rule_id", authorize(["admin"]), removeSuppressionRule);

module.exports = router;
