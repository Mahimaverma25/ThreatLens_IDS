const router = require("express").Router();
const { body } = require("express-validator");

// ✅ Correct validator (NOT API key middleware)
const validate = require("../middleware/validate.middleware");

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
      .withMessage("Username must be at least 2 characters")
  ],
  validate,
  asyncHandler(register)
);

/* ========================
   LOGIN (FIXED)
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
  validate,
  asyncHandler(login)
);

/* ========================
   AUTH ACTIONS
======================== */
router.post("/refresh", asyncHandler(refresh));
router.post("/logout", asyncHandler(logout));
router.get("/me", authenticate, asyncHandler(me));

module.exports = router;