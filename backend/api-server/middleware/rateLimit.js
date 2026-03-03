const rateLimit = require("express-rate-limit");
const config = require("../config/env");

const apiLimiter = rateLimit({
	windowMs: config.rateLimitWindowMs,
	max: config.rateLimitMax,
	standardHeaders: true,
	legacyHeaders: false,
	message: { message: "Too many requests, please try again later." }
});

const authLimiter = rateLimit({
	windowMs: config.rateLimitWindowMs,
	max: config.authRateLimitMax,
	standardHeaders: true,
	legacyHeaders: false,
	message: { message: "Too many auth attempts, please try again later." }
});

module.exports = { apiLimiter, authLimiter };
