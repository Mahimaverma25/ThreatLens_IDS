const router = require("express").Router();
const { body } = require("express-validator");

const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin, authorizeViewer } = require("../middleware/authorize.middleware");
const { validateRequest } = require("../middleware/validate.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  listAlerts,
  getAlertById,
  updateAlertStatus
} = require("../controllers/alerts.controller");

router.get("/", authenticate, authorizeViewer, asyncHandler(listAlerts));

router.get("/:id", authenticate, authorizeViewer, asyncHandler(getAlertById));

router.patch(
  "/:id",
  authenticate,
  authorizeAdmin,
  [
    body("status")
      .optional()
      .isIn(["New", "Acknowledged", "Investigating", "Resolved", "False Positive"]),
    body("note")
      .optional()
      .isLength({ min: 2 })
  ],
  validateRequest,   // ✅ FIXED
  asyncHandler(updateAlertStatus)
);

module.exports = router;
