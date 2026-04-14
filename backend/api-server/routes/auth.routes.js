const router = require("express").Router();
const { body } = require("express-validator");

const { validateRequest } = require("../middleware/validate.middleware");
const authenticate = require("../middleware/auth.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  register,
  login,
  me,
  refresh,
  logout,
  verifyEmail,
  resendVerification
} = require("../controllers/authEmailVerification.controller");

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
      .withMessage("Username must be at least 2 characters")
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
      .withMessage("Password is required")
  ],
  validateRequest,
  asyncHandler(login)
);

router.post(
  "/verify-email",
  [
    body("email")
      .trim()
      .isEmail()
      .withMessage("Valid email is required")
      .normalizeEmail(),

    body("token")
      .trim()
      .notEmpty()
      .withMessage("Verification token is required")
  ],
  validateRequest,
  asyncHandler(verifyEmail)
);

router.post(
  "/resend-verification",
  [
    body("email")
      .trim()
      .isEmail()
      .withMessage("Valid email is required")
      .normalizeEmail()
  ],
  validateRequest,
  asyncHandler(resendVerification)
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
