const morgan = require("morgan");
const Log = require("../models/Log");
const { evaluateLog } = require("../services/detector.service");

const SKIP_ENDPOINT_PREFIXES = [
  "/health",
  "/api/dashboard",
  "/api/logs",
  "/api/alerts",
  "/api/auth/me",
  "/api/auth/refresh",
];

const requestLogger = morgan(
  (tokens, req, res) => {
    const rawStatus = tokens.status(req, res);
    const rawResponseTime = tokens["response-time"](req, res);
    const status = Number.parseInt(rawStatus || "0", 10) || 0;
    const responseTimeMs = Number.parseFloat(rawResponseTime || "0") || 0;
    const level = status >= 500 ? "error" : status >= 400 ? "warn" : "info";
    const url = tokens.url(req, res) || "";
    const shouldPersist = !SKIP_ENDPOINT_PREFIXES.some((prefix) => url.startsWith(prefix));

    if (req.orgId && shouldPersist) {
      Log.create({
        _org_id: req.orgId,
        message: `${tokens.method(req, res)} ${url}`,
        level,
        source: "request",
        ip: req.ip,
        userId: req.user?.sub,
        endpoint: url,
        method: tokens.method(req, res),
        statusCode: status,
        eventType: "request",
        metadata: {
          responseTimeMs
        }
      })
        .then((log) => evaluateLog(log))
        .catch(() => {});
    }

    return `${tokens.method(req, res)} ${url} ${status}`;
  }
);

module.exports = requestLogger;
