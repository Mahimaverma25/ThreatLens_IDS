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
const userRoutes = require("./routes/user.routes");

const app = express();
const server = http.createServer(app);

app.set("trust proxy", 1);

/* --------------------------------- Helpers -------------------------------- */

const normalizeOrigins = (origins) => {
  if (!origins) return [];

  if (Array.isArray(origins)) {
    return origins
      .map((origin) => String(origin).trim())
      .filter(Boolean);
  }

  if (typeof origins === "string") {
    return origins
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean);
  }

  return [];
};

const allowedOrigins = normalizeOrigins(
  config.corsOrigins || config.corsOrigin || process.env.CORS_ORIGIN
);

const isAllowedOrigin = (origin) => {
  if (!origin) return true; // Postman, curl, server-to-server

  if (allowedOrigins.length === 0) return true; // fallback for dev

  if (config.nodeEnv !== "production") {
    try {
      const parsed = new URL(origin);
      const isLocalHost =
        parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";

      if (isLocalHost) {
        return true;
      }
    } catch {
      // Ignore parse errors and continue with strict matching below.
    }
  }

  return allowedOrigins.includes(origin);
};

let io = null;
let isShuttingDown = false;

/* ------------------------------- Middleware -------------------------------- */

app.use(helmet());

app.use(
  cors({
    origin: (origin, callback) => {
      if (isAllowedOrigin(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS origin not allowed: ${origin}`));
    },
    credentials: true,
  })
);

app.use(cookieParser());

app.use(
  express.json({
    limit: config.bodyLimit || "10mb",
    verify: (req, res, buffer) => {
      req.rawBody = buffer.toString("utf8");
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: config.bodyLimit || "10mb",
  })
);

app.use(requestLogger);
app.use(apiLimiter);

/* -------------------------------- Routes ---------------------------------- */

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    status: "OK",
    message: "ThreatLens backend running",
    service: "api-server",
    environment: config.nodeEnv || process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "OK",
    message: "ThreatLens backend healthy",
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv || process.env.NODE_ENV || "development",
    database:
      mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    idsEngineUrl: config.idsEngineUrl || null,
  });
});

app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/agents", agentsRoutes);
app.use("/api/logs", logsRoutes);

app.use("/api/alerts", authenticate, orgIsolation, alertRoutes);
app.use("/api/dashboard", authenticate, orgIsolation, dashboardRoutes);
app.use("/api/intel", authenticate, orgIsolation, intelRoutes);
app.use("/api/incidents", authenticate, orgIsolation, incidentsRoutes);
app.use("/api/reports", authenticate, orgIsolation, reportRoutes);
app.use("/api/playbooks", authenticate, orgIsolation, playbooksRoutes);
app.use("/api/rules", authenticate, orgIsolation, rulesRoutes);
app.use("/api/assets", authenticate, orgIsolation, assetRoutes);
app.use("/api/admin/api-keys", authenticate, orgIsolation, apikeyRoutes);
app.use("/api/users", authenticate, orgIsolation, userRoutes);

/* ----------------------------- 404 / Errors -------------------------------- */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
    path: req.originalUrl,
  });
});

app.use((err, req, res, next) => {
  console.error("Server Error:", err);

  if (res.headersSent) {
    return next(err);
  }

  if (err.message && err.message.includes("CORS origin not allowed")) {
    return res.status(403).json({
      success: false,
      message: err.message,
    });
  }

  return res.status(err.statusCode || 500).json({
    success: false,
    message:
      config.nodeEnv === "production"
        ? "Internal Server Error"
        : err.message || "Internal Server Error",
  });
});

/* ------------------------------ Socket init -------------------------------- */

io = initSocket(server);

/* ---------------------------- Server bootstrap ----------------------------- */

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

    let preferredPort = Number(config.port || process.env.PORT || 5001);
    let activePort = preferredPort;
    const maxPortRetries = Number(process.env.PORT_RETRY_COUNT || 5);

    for (let attempt = 0; attempt <= maxPortRetries; attempt += 1) {
      try {
        await tryListen(activePort);

        console.log(`ThreatLens API running on port ${activePort}`);
        console.log(`Root: http://localhost:${activePort}/`);
        console.log(`Health: http://localhost:${activePort}/health`);
        console.log("Socket.IO initialized");
        console.log(
          `Event stream mode: ${streamState.mode}${
            streamState.key ? ` (${streamState.key})` : ""
          }`
        );
        console.log(
          `Allowed CORS origins: ${
            allowedOrigins.length ? allowedOrigins.join(", ") : "ALL (dev fallback)"
          }`
        );

        return;
      } catch (error) {
        if (error.code === "EADDRINUSE") {
          if (attempt < maxPortRetries) {
            console.warn(
              `Port ${activePort} is already in use. Trying port ${activePort + 1}...`
            );
            activePort += 1;
            continue;
          }

          console.error(
            `Port ${preferredPort} is already in use, and no free fallback port was found after ${maxPortRetries + 1} attempts.`
          );
          process.exit(1);
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

/* ---------------------------- Graceful shutdown ---------------------------- */

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

startServer();
