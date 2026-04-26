const rateLimit = require("express-rate-limit");
const config = require("../config/env");

const READ_ONLY_PATTERNS = [
	/^\/health$/,
	/^\/socket\.io/,
	/^\/api\/dashboard(?:\/|$)/,
	/^\/api\/alerts(?:\/[^/]+)?$/,
	/^\/api\/logs(?:\/)?$/,
	/^\/api\/reports(?:\/)?$/,
	/^\/api\/assets(?:\/[^/]+)?$/,
	/^\/api\/users\/me$/,
];

const isReadOnlyRoute = (req) => {
	if (req.method !== "GET") {
		return false;
	}

	const path = req.path || req.originalUrl || req.url || "";
	return READ_ONLY_PATTERNS.some((pattern) => pattern.test(path));
};

const apiLimiter = rateLimit({
	windowMs: config.rateLimitWindowMs,
	max: config.rateLimitMax,
	skip: (req) => {
		return (
			req.path === "/api/logs/ingest" ||
			isReadOnlyRoute(req)
		);
	},
	keyGenerator: (req) => `${req.ip}:${req.user?.sub || "anonymous"}`,
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

const agentLimiter = rateLimit({
	windowMs: config.rateLimitWindowMs,
	max: config.agentRateLimitMax,
	standardHeaders: true,
	legacyHeaders: false,
	keyGenerator: (req) =>
		String(req.headers["x-api-key"] || req.headers["x-asset-id"] || req.ip || "unknown"),
	message: { message: "Too many ingest requests, please try again later." }
});

module.exports = { apiLimiter, authLimiter, agentLimiter };
