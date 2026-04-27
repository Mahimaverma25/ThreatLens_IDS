const router = require("express").Router();
const { body } = require("express-validator");
const { ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER } = require("../utils/roles");

const { validateRequest } = require("../middleware/validate.middleware");
const authenticate = require("../middleware/auth.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  register,
  login,
  me,
  refresh,
  logout
} = require("../controllers/auth.controller");

/* ========================
   REGISTER
======================== */
router.post(
  "/register",
  [
    body("email")
      .trim()
      .isEmail()
      .withMessage("Valid email is required")
      .normalizeEmail(),

    body("password")
      .trim()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters"),

    body("username")
      .optional()
      .trim()
      .isLength({ min: 2 })
      .withMessage("Username must be at least 2 characters"),

    body("role")
      .optional()
      .trim()
      .isIn([ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, "user"])
      .withMessage("Role must be admin, analyst, or viewer"),

    body("accessCode").optional().trim()
  ],
  validateRequest,
  asyncHandler(register)
);

/* ========================
   LOGIN
======================== */
router.post(
  "/login",
  [
    body("email")
      .trim()
      .isEmail()
      .withMessage("Valid email is required"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required"),

    body("role")
      .optional()
      .trim()
      .isIn([ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, "user"])
      .withMessage("Role must be admin, analyst, or viewer")
  ],
  validateRequest,
  asyncHandler(login)
);

/* ========================
   AUTH ACTIONS
======================== */

// 🔥 FIX 1: refresh should validate token existence
router.post(
  "/refresh",
  asyncHandler(refresh)
);

router.post("/logout", asyncHandler(logout));

// 🔥 FIX 3: me route already correct
router.get(
  "/me",
  authenticate,
  asyncHandler(me)
);

module.exports = router;
