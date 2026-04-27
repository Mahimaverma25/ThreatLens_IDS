const router = require("express").Router();

const authenticate = require("../middleware/auth.middleware");
const {
  authorizeViewer,
  authorizeAnalyst,
} = require("../middleware/authorize.middleware");

const asyncHandler = require("../utils/asyncHandler");

const {
  listIncidents,
  getIncident,
  updateIncident,
  createIncident,
  createIncidentFromAlert,
} = require("../controllers/incidents.controller");

router.use(authenticate);

router.get("/", authorizeViewer, asyncHandler(listIncidents));
router.get("/:id", authorizeViewer, asyncHandler(getIncident));

router.post("/", authorizeAnalyst, asyncHandler(createIncident));
router.post("/from-alert/:alertId", authorizeAnalyst, asyncHandler(createIncidentFromAlert));

router.patch("/:id", authorizeAnalyst, asyncHandler(updateIncident));

module.exports = router;