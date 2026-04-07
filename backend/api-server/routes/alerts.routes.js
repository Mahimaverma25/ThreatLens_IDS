const router = require("express").Router();
const { body } = require("express-validator");

const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const validate = require("../middleware/validate.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
	listAlerts,
	getAlertById,
	updateAlertStatus,
	scanAndStore
} = require("../controllers/alerts.controller");

router.get("/", authenticate, asyncHandler(listAlerts));

router.get("/:id", authenticate, asyncHandler(getAlertById));

router.patch(
	"/:id",
	authenticate,
	authorize(["admin", "analyst"]),
	[
		body("status")
			.optional()
			.isIn(["New", "Acknowledged", "Investigating", "Resolved", "False Positive"]),
		body("note")
			.optional()
			.isLength({ min: 2 })
	],
	validate,
	asyncHandler(updateAlertStatus)
);

router.post(
	"/scan",
	authenticate,
	authorize(["admin", "analyst"]),
	asyncHandler(scanAndStore)
);

module.exports = router;