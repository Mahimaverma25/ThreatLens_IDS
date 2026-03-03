const router = require("express").Router();
const { body } = require("express-validator");
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const validate = require("../middleware/validate.middleware");
const {
	listAlerts,
	getAlertById,
	updateAlertStatus,
	scanAndStore
} = require("../controllers/alerts.controller");

router.get("/", authenticate, listAlerts);
router.get("/:id", authenticate, getAlertById);
router.patch(
	"/:id",
	authenticate,
	authorize(["admin", "analyst"]),
	[body("status").optional().isIn(["New", "Acknowledged", "Investigating", "Resolved", "False Positive"]), body("note").optional().isLength({ min: 2 })],
	validate,
	updateAlertStatus
);
router.post("/scan", authenticate, authorize(["admin", "analyst"]), scanAndStore);

module.exports = router;
