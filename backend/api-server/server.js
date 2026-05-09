require("dotenv").config();

const cookieParser = require("cookie-parser");
const cors = require("cors");
const express = require("express");
const helmet = require("helmet");
const http = require("http");
const mongoose = require("mongoose");

const config = require("./config/env");
const { connectDB } = require("./config/db");

const authenticate = require("./middleware/auth.middleware");
const { orgIsolation } = require("./middleware/orgIsolation.middleware");
const { apiLimiter, authLimiter } = require("./middleware/rateLimit");
const requestLogger = require("./middleware/requestLogger");

const { initEventStream } = require("./services/event-stream.service");
const { initSocket } = require("./services/socket.service");

const alertRoutes = require("./routes/alerts.routes");
const agentsRoutes = require("./routes/agents.routes");
const apikeyRoutes = require("./routes/apikey.routes");
const assetRoutes = require("./routes/asset.routes");
const authRoutes = require("./routes/auth.routes");
const dashboardRoutes = require("./routes/dashboard.routes");
const incidentsRoutes = require("./routes/incidents.routes");
const intelRoutes = require("./routes/intel.routes");
const logsRoutes = require("./routes/logs.routes");
const playbooksRoutes = require("./routes/playbooks.routes");
const reportRoutes = require("./routes/report.routes");
const rulesRoutes = require("./routes/rules.routes");
const settingsRoutes = require("./routes/settings.routes");
const userRoutes = require("./routes/user.routes");

const app = express();
const server = http.createServer(app);

app.set("trust proxy", 1);

let isShuttingDown = false;

const normalizeOrigins = (origins) => {
  if (!origins) return [];

  if (Array.isArray(origins)) {
    return origins.map((origin) => String(origin).trim()).filter(Boolean);
  }

  return String(origins)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
};

const allowedOrigins = normalizeOrigins(
  config.corsOrigins || config.corsOrigin || process.env.CORS_ORIGIN
);

const isAllowedOrigin = (origin) => {
  if (!origin) return true;

  if (allowedOrigins.length === 0) {
    return config.nodeEnv !== "production";
  }

  if (config.nodeEnv !== "production") {
    try {
      const parsed = new URL(origin);

      if (
        parsed.hostname === "localhost" ||
        parsed.hostname === "127.0.0.1"
      ) {
        return true;
      }
    } catch {
      return false;
    }
  }

  return allowedOrigins.includes(origin);
};

const corsOptions = {
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) return callback(null, true);
    return callback(new Error(`CORS origin not allowed: ${origin}`));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-API-Key",
    "X-Timestamp",
    "X-Signature",
    "X-Signature-Version",
    "X-Nonce",
    "X-Asset-ID",
    "X-Agent-Version",
    "x-api-key",
    "x-timestamp",
    "x-signature",
    "x-signature-version",
    "x-nonce",
    "x-asset-id",
    "x-agent-version",
  ],
};

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(cookieParser());

app.use(
  express.json({
    limit: config.bodyLimit || process.env.BODY_LIMIT || "10mb",
    verify: (req, res, buffer) => {
      req.rawBody = buffer.toString("utf8");
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: config.bodyLimit || process.env.BODY_LIMIT || "10mb",
  })
);

app.use(requestLogger);
app.use(apiLimiter);

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    status: "OK",
    message: "ThreatLens backend running",
    service: "api-server",
    environment: config.nodeEnv || process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString(),
    endpoints: {
      health: "/health",
      auth: "/api/auth",
      logs: "/api/logs",
      agents: "/api/agents",
      dashboard: "/api/dashboard",
      alerts: "/api/alerts",
      incidents: "/api/incidents",
    },
  });
});

app.get("/health", (req, res) => {
  const dbConnected = mongoose.connection.readyState === 1;

  res.status(dbConnected ? 200 : 503).json({
    success: dbConnected,
    status: dbConnected ? "OK" : "DEGRADED",
    message: dbConnected
      ? "ThreatLens backend healthy"
      : "ThreatLens backend running but database disconnected",
    service: "api-server",
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv || process.env.NODE_ENV || "development",
    database: dbConnected ? "connected" : "disconnected",
    idsEngineUrl: config.idsEngineUrl || process.env.IDS_ENGINE_URL || null,
  });
});

/**
 * Public routes.
 */
app.use("/api/auth", authLimiter, authRoutes);

/**
 * Agent routes.
 * These stay public here because they use API key + HMAC inside route middleware.
 */
app.use("/api/logs", logsRoutes);
app.use("/api/agents", agentsRoutes);

/**
 * Protected SOC/dashboard routes.
 */
app.use("/api/alerts", authenticate, orgIsolation, alertRoutes);
app.use("/api/dashboard", authenticate, orgIsolation, dashboardRoutes);
app.use("/api/intel", authenticate, orgIsolation, intelRoutes);
app.use("/api/incidents", authenticate, orgIsolation, incidentsRoutes);
app.use("/api/reports", authenticate, orgIsolation, reportRoutes);
app.use("/api/playbooks", authenticate, orgIsolation, playbooksRoutes);
app.use("/api/rules", authenticate, orgIsolation, rulesRoutes);
app.use("/api/assets", authenticate, orgIsolation, assetRoutes);
app.use("/api/admin/api-keys", authenticate, orgIsolation, apikeyRoutes);
app.use("/api/settings", authenticate, orgIsolation, settingsRoutes);
app.use("/api/users", authenticate, orgIsolation, userRoutes);

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
    method: req.method,
    path: req.originalUrl,
  });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  console.error("Server Error:", err);

  if (err.message && err.message.includes("CORS origin not allowed")) {
    return res.status(403).json({
      success: false,
      message: err.message,
    });
  }

  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({
      success: false,
      message: "Invalid JSON payload",
    });
  }

  return res.status(err.statusCode || err.status || 500).json({
    success: false,
    message:
      config.nodeEnv === "production"
        ? "Internal Server Error"
        : err.message || "Internal Server Error",
  });
});

initSocket(server);

const tryListen = (port) =>
  new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };

    const onListening = () => {
      server.off("error", onError);
      resolve();
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port);
  });

const startServer = async () => {
  try {
    await connectDB();

    const streamState = await initEventStream();

    const preferredPort = Number(config.port || process.env.PORT || 5001);
    let activePort = preferredPort;
    const maxPortRetries = Number(process.env.PORT_RETRY_COUNT || 5);

    for (let attempt = 0; attempt <= maxPortRetries; attempt += 1) {
      try {
        await tryListen(activePort);

        console.log(`ThreatLens API running on port ${activePort}`);
        console.log(`Root:   http://localhost:${activePort}/`);
        console.log(`Health: http://localhost:${activePort}/health`);
        console.log(`Socket.IO initialized`);
        console.log(
          `Event stream mode: ${streamState?.mode || "memory"}${
            streamState?.key ? ` (${streamState.key})` : ""
          }`
        );
        console.log(
          `Allowed CORS origins: ${
            allowedOrigins.length
              ? allowedOrigins.join(", ")
              : "LOCAL DEVELOPMENT ONLY"
          }`
        );

        return;
      } catch (error) {
        if (error.code === "EADDRINUSE" && attempt < maxPortRetries) {
          console.warn(
            `Port ${activePort} is already in use. Trying port ${
              activePort + 1
            }...`
          );
          activePort += 1;
          continue;
        }

        console.error("Server listen error:", error.message);
        process.exit(1);
      }
    }
  } catch (error) {
    console.error("Failed to start server:", error.message);
    process.exit(1);
  }
};

const shutdown = async (signal) => {
  if (isShuttingDown) return;

  isShuttingDown = true;

  console.log(`\n${signal} received. Shutting down ThreatLens backend...`);

  try {
    await new Promise((resolve) => {
      server.close(() => resolve());
    });

    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
      console.log("MongoDB connection closed");
    }

    console.log("ThreatLens backend stopped cleanly");
    process.exit(0);
  } catch (error) {
    console.error("Error during shutdown:", error.message);
    process.exit(1);
  }
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

process.on("uncaughtException", async (error) => {
  console.error("Uncaught Exception:", error);
  await shutdown("uncaughtException");
});

process.on("unhandledRejection", async (reason) => {
  console.error("Unhandled Rejection:", reason);
  await shutdown("unhandledRejection");
});

module.exports = {
  app,
  server,
  startServer,
};

if (require.main === module) {
  startServer();
}