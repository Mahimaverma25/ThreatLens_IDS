const rateLimit = require("express-rate-limit");

const createLimiter = ({ windowMs, max, message }) =>
	rateLimit({
		windowMs,
		max,
		standardHeaders: true,
		legacyHeaders: false,
		message: { message }
	});

const strictLimiter = createLimiter({
	windowMs: 60 * 1000,
	max: 30,
	message: "Too many requests from this IP"
});

const ingestLimiter = createLimiter({
	windowMs: 60 * 1000,
	max: 300,
	message: "Ingest rate limit exceeded"
});

module.exports = {
	strictLimiter,
	ingestLimiter
};
