const dotenv = require("dotenv");

dotenv.config();

const getNumber = (value, fallback) => {
	const parsed = Number.parseInt(value, 10);
	return Number.isNaN(parsed) ? fallback : parsed;
};

const getList = (value, fallback) => {
	if (!value || !value.trim()) {
		return fallback;
	}

	return value
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
};

module.exports = {
	nodeEnv: process.env.NODE_ENV || "development",
	port: getNumber(process.env.PORT, 5000),
	mongoUri: process.env.MONGO_URI || "mongodb://127.0.0.1:27017/threatlens",
	frontendBaseUrl: process.env.FRONTEND_BASE_URL || "http://localhost:3000",
	jwtSecret: process.env.JWT_SECRET || "change-me",
	jwtExpiresIn: process.env.JWT_EXPIRES_IN || "1h",
	refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || "change-me-too",
	refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "30d",
	corsOrigins: getList(process.env.CORS_ORIGIN, ["http://localhost:3000"]),
	idsEngineUrl: process.env.IDS_ENGINE_URL || "http://localhost:8000",
	rateLimitWindowMs: getNumber(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
	rateLimitMax: getNumber(process.env.RATE_LIMIT_MAX, 1000),
	authRateLimitMax: getNumber(process.env.AUTH_RATE_LIMIT_MAX, 15),
	bodyLimit: process.env.BODY_LIMIT || "1mb",
	refreshCookieName: process.env.REFRESH_COOKIE_NAME || "threatlens_rt",
	refreshCookieDomain: process.env.REFRESH_COOKIE_DOMAIN || undefined,
	refreshCookieSecure: process.env.REFRESH_COOKIE_SECURE === "true",
	refreshCookieSameSite: process.env.REFRESH_COOKIE_SAMESITE || "lax",
	emailVerificationExpiryMinutes: getNumber(process.env.EMAIL_VERIFICATION_EXPIRY_MINUTES, 30),
	smtpHost: process.env.SMTP_HOST || "",
	smtpPort: getNumber(process.env.SMTP_PORT, 587),
	smtpSecure: process.env.SMTP_SECURE === "true",
	smtpUser: process.env.SMTP_USER || "",
	smtpPass: process.env.SMTP_PASS || "",
	smtpFrom: process.env.SMTP_FROM || "ThreatLens <no-reply@threatlens.local>",
	integrationApiKey: process.env.INTEGRATION_API_KEY || "",
	requestLogLevel: process.env.REQUEST_LOG_LEVEL || "info",
	alertCorrelationWindowMins: getNumber(process.env.ALERT_CORRELATION_WINDOW_MINS, 10),
	dosThresholdPerMinute: getNumber(process.env.DOS_THRESHOLD_PER_MINUTE, 150),
	bruteforceThreshold: getNumber(process.env.BRUTE_FORCE_THRESHOLD, 5)
};
