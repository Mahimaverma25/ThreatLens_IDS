const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");
const {
  createAsset,
  listAssets,
  getAsset,
  updateAsset,
  deleteAsset,
  addSuppressionRule,
  removeSuppressionRule
} = require("../controllers/asset.controller");

// All asset routes require authentication (org isolation applied at app level)
router.use(authenticate);

// List assets
router.get("/", asyncHandler(listAssets));

// Get asset details
router.get("/:id", asyncHandler(getAsset));

// Create asset (admin only)
router.post("/", authorize(["admin"]), asyncHandler(createAsset));

// Update asset (admin only)
router.patch("/:id", authorize(["admin"]), asyncHandler(updateAsset));

// Delete asset (admin only)
router.delete("/:id", authorize(["admin"]), asyncHandler(deleteAsset));

// Add suppression rule (admin only)
router.post("/:id/suppression-rules", authorize(["admin"]), asyncHandler(addSuppressionRule));

// Remove suppression rule (admin only)
router.delete("/:id/suppression-rules/:rule_id", authorize(["admin"]), asyncHandler(removeSuppressionRule));

module.exports = router;
