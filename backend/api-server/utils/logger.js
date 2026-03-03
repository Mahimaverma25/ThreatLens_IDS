const fs = require("fs");
const path = require("path");
const winston = require("winston");

const logsDir = path.join(__dirname, "..", "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const baseFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.printf(({ level, message, timestamp, ...meta }) => {
    const metaString = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : "";
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

module.exports = { appLogger, auditLogger };
