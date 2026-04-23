const router = require("express").Router();

const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin, authorizeAnalyst, authorizeViewer } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");
const {
  listIncidents,
  getIncident,
  updateIncident,
} = require("../controllers/incidents.controller");

router.use(authenticate);

router.get("/", authorizeViewer, asyncHandler(listIncidents));
router.get("/:id", authorizeViewer, asyncHandler(getIncident));
router.patch("/:id", authorizeAnalyst, asyncHandler(updateIncident));

module.exports = router;
