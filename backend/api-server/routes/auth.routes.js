const router = require("express").Router();
const { body } = require("express-validator");
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

// ========================
// REGISTER
// ========================
router.post(
  "/register",
  [
    body("email")
      .isEmail()
      .withMessage("Valid email is required")
      .normalizeEmail(),

    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters"),

    body("username")
      .optional()
      .isLength({ min: 2 })
      .withMessage("Username must be at least 2 characters")
  ],
  validate,
  asyncHandler(register)
);

// ========================
// LOGIN
// ========================
router.post(
  "/login",
  [
    body("email")
      .isEmail()
      .withMessage("Valid email is required"),

    body("password")
      .notEmpty()
      .withMessage("Password is required")
  ],
  validate,
  asyncHandler(login)
);

// ========================
// AUTH ACTIONS
// ========================
router.post("/refresh", asyncHandler(refresh));
router.post("/logout", asyncHandler(logout));
router.get("/me", authenticate, asyncHandler(me));

module.exports = router;