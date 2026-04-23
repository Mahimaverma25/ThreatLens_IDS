const router = require("express").Router();

const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin, authorizeViewer } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");
const {
  getThreatIntel,
  getThreatMap,
  getModelHealthDetails,
  createThreatIndicator,
  listThreatIndicators,
  deleteThreatIndicator,
} = require("../controllers/intel.controller");

router.use(authenticate, authorizeViewer);

router.get("/threat-intel", asyncHandler(getThreatIntel));
router.get("/threat-map", asyncHandler(getThreatMap));
router.get("/model-health", asyncHandler(getModelHealthDetails));
router.get("/watchlist", asyncHandler(listThreatIndicators));
router.post("/watchlist", authorizeAdmin, asyncHandler(createThreatIndicator));
router.delete("/watchlist/:id", authorizeAdmin, asyncHandler(deleteThreatIndicator));

module.exports = router;
