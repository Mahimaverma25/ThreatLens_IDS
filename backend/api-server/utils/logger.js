const fs = require("fs");
const path = require("path");
const winston = require("winston");

const REDACTED_KEYS = [
  "authorization",
  "cookie",
  "jwt",
  "jwtSecret",
  "refreshTokenSecret",
  "secret",
  "secret_key_hash",
  "token",
  "x-api-key",
  "x-signature",
  "x-integration-api-key",
  "mongoUri",
];

const sanitizeForLogs = (value) => {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeForLogs(item));
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  return Object.entries(value).reduce((result, [key, entryValue]) => {
    if (REDACTED_KEYS.includes(key)) {
      result[key] = "[REDACTED]";
      return result;
    }

    result[key] = sanitizeForLogs(entryValue);
    return result;
  }, {});
};

const serializeError = (error) =>
  sanitizeForLogs({
    name: error?.name,
    message: error?.message,
    code: error?.code,
    status: error?.status,
    statusCode: error?.statusCode,
    response: error?.response?.data,
  });

const logsDir = path.join(__dirname, "..", "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const baseFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.printf(({ level, message, timestamp, ...meta }) => {
    const sanitizedMeta = sanitizeForLogs(meta);
    const metaString = Object.keys(sanitizedMeta).length ? ` ${JSON.stringify(sanitizedMeta)}` : "";
    return `${timestamp} ${level} ${message}${metaString}`;
  })
);

const appLogger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: baseFormat,
  transports: [
    new winston.transports.File({ filename: path.join(logsDir, "app.log") }),
    new winston.transports.Console()
  ]
});

const auditLogger = winston.createLogger({
  level: "info",
  format: baseFormat,
  transports: [
    new winston.transports.File({ filename: path.join(logsDir, "audit.log") })
  ]
});

module.exports = { appLogger, auditLogger, sanitizeForLogs, serializeError };
