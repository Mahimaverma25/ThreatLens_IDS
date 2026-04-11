const { body } = require("express-validator");

const createLogValidator = [
	body("message").trim().notEmpty().withMessage("message is required"),
	body("level").optional().isIn(["info", "warn", "error"]).withMessage("Invalid log level"),
	body("source").optional().isString().withMessage("source must be a string")
];

const ingestLogValidator = [
	body("logs").isArray({ min: 1 }).withMessage("logs array is required"),
	body("logs.*.message").notEmpty().withMessage("each log must include message")
];

module.exports = {
	createLogValidator,
	ingestLogValidator
};
