const { body } = require("express-validator");

const registerValidator = [
	body("email").trim().isEmail().withMessage("Valid email is required").normalizeEmail(),
	body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters"),
	body("username").optional().trim().isLength({ min: 2 }).withMessage("Username must be at least 2 characters")
];

const loginValidator = [
	body("email").trim().isEmail().withMessage("Valid email is required").normalizeEmail(),
	body("password").notEmpty().withMessage("Password is required")
];

module.exports = {
	registerValidator,
	loginValidator
};
