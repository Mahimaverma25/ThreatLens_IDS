const dotenv = require("dotenv");

dotenv.config();

const isProduction = String(process.env.NODE_ENV || "development").toLowerCase() === "production";

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

const getRequiredSecret = (name, developmentFallback) => {
	if (process.env[name] && String(process.env[name]).trim()) {
		return String(process.env[name]).trim();
	}

	if (isProduction) {
		throw new Error(`${name} is required in production`);
	}

	return developmentFallback;
};

const mongoUri =
	process.env.MONGO_URI && String(process.env.MONGO_URI).trim()
		? String(process.env.MONGO_URI).trim()
		: "mongodb://127.0.0.1:27017/threatlens";

const corsOrigins = getList(process.env.CORS_ORIGIN, ["http://localhost:3000"]);
const enableIdsAnalysis = process.env.ENABLE_IDS_ANALYSIS !== "false";
const integrationApiKey = process.env.INTEGRATION_API_KEY
	? String(process.env.INTEGRATION_API_KEY).trim()
	: "";

if (isProduction && corsOrigins.length === 0) {
	throw new Error("CORS_ORIGIN must be configured in production");
}

if (isProduction && (!process.env.MONGO_URI || !String(process.env.MONGO_URI).trim())) {
	throw new Error("MONGO_URI is required in production");
}

if (isProduction && enableIdsAnalysis && !integrationApiKey) {
	throw new Error("INTEGRATION_API_KEY is required when IDS analysis is enabled in production");
}

module.exports = {
	nodeEnv: process.env.NODE_ENV || "development",
	port: getNumber(process.env.PORT, 5000),
	mongoUri,
	frontendBaseUrl: process.env.FRONTEND_BASE_URL || "http://localhost:3000",
	jwtSecret: getRequiredSecret("JWT_SECRET", "dev-local-access-secret"),
	jwtExpiresIn: process.env.JWT_EXPIRES_IN || "1h",
	refreshTokenSecret: getRequiredSecret("REFRESH_TOKEN_SECRET", "dev-local-refresh-secret"),
	refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "30d",
	corsOrigins,
	idsEngineUrl: process.env.IDS_ENGINE_URL || "http://localhost:8000",
	rateLimitWindowMs: getNumber(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
	rateLimitMax: getNumber(process.env.RATE_LIMIT_MAX, 1000),
	authRateLimitMax: getNumber(process.env.AUTH_RATE_LIMIT_MAX, 15),
	agentRateLimitMax: getNumber(process.env.AGENT_RATE_LIMIT_MAX, 300),
	bodyLimit: process.env.BODY_LIMIT || "1mb",
	uploadBodyLimit: process.env.UPLOAD_BODY_LIMIT || "20mb",
	maxUploadFileSizeBytes: getNumber(process.env.MAX_UPLOAD_FILE_SIZE_BYTES, 20 * 1024 * 1024),
	refreshCookieName: process.env.REFRESH_COOKIE_NAME || "threatlens_rt",
	refreshCookieDomain: process.env.REFRESH_COOKIE_DOMAIN || undefined,
	refreshCookieSecure: process.env.REFRESH_COOKIE_SECURE === "true",
	refreshCookieSameSite: process.env.REFRESH_COOKIE_SAMESITE || "lax",
	enableIdsAnalysis,
	integrationApiKey,
	requestLogLevel: process.env.REQUEST_LOG_LEVEL || "info",
	alertCorrelationWindowMins: getNumber(process.env.ALERT_CORRELATION_WINDOW_MINS, 10),
	dosThresholdPerMinute: getNumber(process.env.DOS_THRESHOLD_PER_MINUTE, 150),
	bruteforceThreshold: getNumber(process.env.BRUTE_FORCE_THRESHOLD, 5),
	ingestBatchLimit: getNumber(process.env.INGEST_BATCH_LIMIT, 500),
	ingestSignatureToleranceMs: getNumber(process.env.INGEST_SIGNATURE_TOLERANCE_MS, 5 * 60 * 1000),
	ingestNonceTtlMs: getNumber(process.env.INGEST_NONCE_TTL_MS, 10 * 60 * 1000),
	redisUrl: process.env.REDIS_URL || "",
	redisStreamKey: process.env.REDIS_STREAM_KEY || "threatlens:events",
	redisStreamMaxLen: getNumber(process.env.REDIS_STREAM_MAXLEN, 2000)
};
