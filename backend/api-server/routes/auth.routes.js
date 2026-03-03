const router = require("express").Router();
const { body } = require("express-validator");

const authenticate = require("../middleware/auth.middleware");
const validate = require("../middleware/validate.middleware");
const {
  register,
  login,
  me,
  refresh,
  logout
} = require("../controllers/auth.controller");

// REGISTER
router.post(
  "/register",
  [
    body("email").isEmail().normalizeEmail(),
    body("password").isLength({ min: 8 }),
    body("username").optional().isLength({ min: 2 })
  ],
  validate,
  register
);

// LOGIN
router.post(
  "/login",
  [
    body("email").isEmail(),
    body("password").notEmpty()
  ],
  validate,
  login
);

// AUTH ACTIONS
router.post("/refresh", refresh);
router.post("/logout", logout);
router.get("/me", authenticate, me);

module.exports = router;
