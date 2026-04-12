const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin, authorizeViewer } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");
const {
  getReportSummary,
  exportAlertsCsv,
  exportLogsCsv,
} = require("../controllers/report.controller");

router.get("/", authenticate, authorizeViewer, asyncHandler(getReportSummary));
router.get("/export/alerts.csv", authenticate, authorizeAdmin, asyncHandler(exportAlertsCsv));
router.get("/export/logs.csv", authenticate, authorizeAdmin, asyncHandler(exportLogsCsv));

module.exports = router;
