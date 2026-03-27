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

const alertRoutes = require("./routes/alerts.routes");
const authRoutes = require("./routes/auth.routes");
const logRoutes = require("./routes/logs.routes");
const dashboardRoutes = require("./routes/dashboard.routes");
const apikeyRoutes = require("./routes/apikey.routes");
const assetRoutes = require("./routes/asset.routes");

const app = express();
const server = http.createServer(app);

/* ================= IMPORTANT CONFIG ================= */

// Required for correct IP handling
app.set("trust proxy", 1);

/* ================= SECURITY ================= */

app.use(helmet());
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(cookieParser());

/* ================= BODY PARSER ================= */

app.use(express.json({ limit: config.bodyLimit }));

/* ================= LOGGER ================= */

app.use(requestLogger);

/* ================= RATE LIMIT ================= */

app.use(apiLimiter);

/* ================= DATABASE ================= */

connectDB();

/* ================= HEALTH CHECK ================= */

app.get("/", (req, res) => {
  res.json({ status: "ok", message: "ThreatLens API running" });
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

/* ================= ROUTES ================= */

// 🔐 Auth routes (JWT based)
app.use("/api/auth", authLimiter, authRoutes);

// 🔥 IMPORTANT: Logs route MUST use orgIsolation
// Supports BOTH:
// - Agent (x-api-key + x-org-id)
// - User (JWT)
app.use("/api/logs", orgIsolation, logRoutes);

// 🔐 Protected routes (require org context)
app.use("/api/alerts", orgIsolation, alertRoutes);
app.use("/api/dashboard", orgIsolation, dashboardRoutes);
app.use("/api/assets", orgIsolation, assetRoutes);

// 🔐 Admin routes (should also be protected ideally)
app.use("/api/admin/api-keys", orgIsolation, apikeyRoutes);

/* ================= ERROR HANDLER ================= */

app.use((err, req, res, next) => {
  console.error("❌ Global Error:", err);
  res.status(500).json({ message: "Internal server error" });
});

/* ================= SOCKET ================= */

initSocket(server);

/* ================= SERVER START ================= */

server.listen(config.port, () =>
  console.log(`🚀 ThreatLens API running on port ${config.port}`)
);