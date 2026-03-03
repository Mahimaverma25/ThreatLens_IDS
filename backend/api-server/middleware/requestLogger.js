const morgan = require("morgan");
const Log = require("../models/Log");
const { evaluateLog } = require("../services/detector.service");

const requestLogger = morgan(
  (tokens, req, res) => {
    const status = Number.parseInt(tokens.status(req, res), 10);
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
        responseTimeMs: Number.parseInt(tokens["response-time"](req, res), 10)
      }
    })
      .then((log) => evaluateLog(log))
      .catch(() => {});

    return `${tokens.method(req, res)} ${tokens.url(req, res)} ${status}`;
  }
);

module.exports = requestLogger;
