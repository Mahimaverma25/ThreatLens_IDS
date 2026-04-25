const router = require("express").Router();
const { body } = require("express-validator");

const { getSettings, updateSettings } = require("../controllers/settings.controller");
const { authorizeViewer } = require("../middleware/authorize.middleware");
const { validateRequest } = require("../middleware/validate.middleware");
const asyncHandler = require("../utils/asyncHandler");

router.get("/", authorizeViewer, asyncHandler(getSettings));

router.put(
  "/",
  authorizeViewer,
  [
    body("profile.name")
      .optional()
      .isString()
      .trim()
      .isLength({ min: 0, max: 120 })
      .withMessage("Name must be 120 characters or fewer"),
    body("profile.email")
      .optional()
      .isEmail()
      .withMessage("Valid email is required"),
    body("password.current")
      .optional()
      .isString()
      .withMessage("Current password must be a string"),
    body("password.newPass")
      .optional()
      .isLength({ min: 8 })
      .withMessage("New password must be at least 8 characters"),
    body("system.theme")
      .optional()
      .isIn(["dark", "light"])
      .withMessage("Theme must be dark or light"),
    body("system.notifications")
      .optional()
      .isBoolean()
      .withMessage("Notifications must be a boolean"),
    body("idsConfig.alertThreshold")
      .optional()
      .isInt({ min: 0, max: 100 })
      .withMessage("Alert threshold must be between 0 and 100"),
    body("idsConfig.autoBlock")
      .optional()
      .isBoolean()
      .withMessage("Auto block must be a boolean"),
    body("agentApi.endpoint")
      .optional()
      .isString()
      .trim()
      .isLength({ max: 300 })
      .withMessage("API endpoint must be 300 characters or fewer"),
    body("agentApi.apiKey")
      .optional()
      .isString()
      .trim()
      .isLength({ max: 300 })
      .withMessage("API key must be 300 characters or fewer"),
  ],
  validateRequest,
  asyncHandler(updateSettings)
);

module.exports = router;
