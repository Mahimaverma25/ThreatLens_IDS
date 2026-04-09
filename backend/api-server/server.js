require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const http = require("http");

const config = require("./config/env");
const { connectDB } = require("./config/db");
const { apiLimiter, authLimiter } = require("./middleware/rateLimit");
const requestLogger = require("./middleware/requestLogger");
const { orgIsolation } = require("./middleware/orgIsolation.middleware");
const { initSocket } = require("./socket");

// Routes
const alertRoutes = require("./routes/alerts.routes");
const authRoutes = require("./routes/auth.routes");
const logRoutes = require("./routes/logs.routes");
const dashboardRoutes = require("./routes/dashboard.routes");
const apikeyRoutes = require("./routes/apikey.routes");
const assetRoutes = require("./routes/asset.routes");

const app = express();
const server = http.createServer(app);

/* ================= BASIC CONFIG ================= */

app.set("trust proxy", 1);

/* ================= SECURITY ================= */

app.use(helmet());

app.use(
  cors({
    origin: config.corsOrigin || "http://localhost:3000",
    credentials: true,
  })
);

app.use(cookieParser());

/* ================= BODY PARSER ================= */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================= LOGGER ================= */

app.use(requestLogger);

/* ================= RATE LIMIT ================= */

app.use(apiLimiter);

/* ================= DATABASE ================= */

connectDB();

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
app.use("/api/alerts", orgIsolation, alertRoutes);
app.use("/api/dashboard", orgIsolation, dashboardRoutes);
app.use("/api/assets", orgIsolation, assetRoutes);
app.use("/api/admin/api-keys", orgIsolation, apikeyRoutes);

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

server.listen(config.port, () => {
  console.log(`🚀 ThreatLens API running on port ${config.port}`);
});