require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const http = require("http");

const config = require("./config/env");
const { connectDB } = require("./config/db");
const authenticate = require("./middleware/auth.middleware");
const { apiLimiter, authLimiter } = require("./middleware/rateLimit");
const requestLogger = require("./middleware/requestLogger");
const { orgIsolation } = require("./middleware/orgIsolation.middleware");
const { initSocket } = require("./socket");

// Routes
const alertRoutes = require("./routes/alerts.routes");
const authRoutes = require("./routes/auth.routes");
const logRoutes = require("./routes/log.routes");
const dashboardRoutes = require("./routes/dashboard.routes");
const reportRoutes = require("./routes/report.routes");
const apikeyRoutes = require("./routes/apikey.routes");
const assetRoutes = require("./routes/asset.routes");
const userRoutes = require("./routes/user.routes");

const app = express();
const server = http.createServer(app);

/* ================= BASIC CONFIG ================= */

app.set("trust proxy", 1);

/* ================= SECURITY ================= */

app.use(helmet());

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) {
        return callback(null, true);
      }

      if (config.corsOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS origin not allowed"));
    },
    credentials: true,
  })
);

app.use(cookieParser());

/* ================= BODY PARSER ================= */

app.use(express.json({ limit: config.bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: config.bodyLimit }));

/* ================= LOGGER ================= */

app.use(requestLogger);

/* ================= RATE LIMIT ================= */

app.use(apiLimiter);

/* ================= HEALTH CHECK ================= */

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "ThreatLens Backend Running 🚀",
  });
});

/* ================= ROUTES ================= */

// 🔐 Auth routes
app.use("/api/auth", authLimiter, authRoutes);

// 🔥 Logs route (agent)
app.use("/api/logs", logRoutes);

// 🔐 Protected routes
app.use("/api/alerts", authenticate, orgIsolation, alertRoutes);
app.use("/api/dashboard", authenticate, orgIsolation, dashboardRoutes);
app.use("/api/reports", authenticate, orgIsolation, reportRoutes);
app.use("/api/assets", authenticate, orgIsolation, assetRoutes);
app.use("/api/admin/api-keys", authenticate, orgIsolation, apikeyRoutes);
app.use("/api/users", authenticate, orgIsolation, userRoutes);

/* ================= 404 HANDLER ================= */

app.use((req, res) => {
  res.status(404).json({
    message: "Route not found",
  });
});

/* ================= ERROR HANDLER ================= */

app.use((err, req, res, next) => {
  console.error("Server Error:", err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(err.statusCode || 500).json({
    message:
      process.env.NODE_ENV === "production"
        ? "Internal Server Error"
        : err.message,
  });
});

/* ================= SOCKET ================= */

initSocket(server);

/* ================= SERVER START ================= */
const startServer = async () => {
  await connectDB();

  server.listen(config.port, () => {
    console.log(`🚀 ThreatLens API running on port ${config.port}`);
  });
};

startServer().catch((error) => {
  console.error("Failed to start server:", error.message);
  process.exit(1);
});
