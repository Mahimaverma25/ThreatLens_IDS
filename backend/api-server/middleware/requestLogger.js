const morgan = require("morgan");
const Log = require("../models/Log");
const { evaluateLog } = require("../services/detector.service");

const requestLogger = morgan(
  (tokens, req, res) => {
    const rawStatus = tokens.status(req, res);
    const rawResponseTime = tokens["response-time"](req, res);
    const status = Number.parseInt(rawStatus || "0", 10) || 0;
    const responseTimeMs = Number.parseFloat(rawResponseTime || "0") || 0;
    const level = status >= 500 ? "error" : status >= 400 ? "warn" : "info";

    Log.create({
      message: `${tokens.method(req, res)} ${tokens.url(req, res)}`,
      level,
      source: "request",
      ip: req.ip,
      userId: req.user?.sub,
      endpoint: tokens.url(req, res),
      method: tokens.method(req, res),
      statusCode: status,
      eventType: "request",
      metadata: {
        responseTimeMs
      }
    })
      .then((log) => evaluateLog(log))
      .catch(() => {});

    return `${tokens.method(req, res)} ${tokens.url(req, res)} ${status}`;
  }
);

module.exports = requestLogger;
