const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin, authorizeViewer } = require("../middleware/authorize.middleware");
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
router.get("/", authorizeViewer, asyncHandler(listAssets));

// Get asset details
router.get("/:id", authorizeViewer, asyncHandler(getAsset));

// Create asset (admin only)
router.post("/", authorizeAdmin, asyncHandler(createAsset));

// Update asset (admin only)
router.patch("/:id", authorizeAdmin, asyncHandler(updateAsset));

// Delete asset (admin only)
router.delete("/:id", authorizeAdmin, asyncHandler(deleteAsset));

// Add suppression rule (admin only)
router.post("/:id/suppression-rules", authorizeAdmin, asyncHandler(addSuppressionRule));

// Remove suppression rule (admin only)
router.delete("/:id/suppression-rules/:rule_id", authorizeAdmin, asyncHandler(removeSuppressionRule));

module.exports = router;
