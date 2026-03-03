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
const ingestRoutes = require("./routes/ingest.routes");
const apikeyRoutes = require("./routes/apikey.routes");
const assetRoutes = require("./routes/asset.routes");

const app = express();
const server = http.createServer(app);

// 🔥 VERY IMPORTANT FIX
app.set("trust proxy", 1);

// Security middleware
app.use(helmet());
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(cookieParser());

// Body parser
app.use(express.json({ limit: config.bodyLimit }));

// Logger
app.use(requestLogger);

// Rate limiting (AFTER trust proxy)
app.use(apiLimiter);

connectDB();

app.get("/health", (req, res) => res.json({ status: "ok" }));

// Ingest API
app.use("/api/ingest", ingestRoutes);

// Auth routes
app.use("/api/auth", authLimiter, authRoutes);

// Protected routes
app.use("/api/alerts", orgIsolation, alertRoutes);
app.use("/api/logs", orgIsolation, logRoutes);
app.use("/api/dashboard", orgIsolation, dashboardRoutes);

// Admin routes
app.use("/api/admin/api-keys", apikeyRoutes);
app.use("/api/assets", assetRoutes);

// Global error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Internal server error" });
});

initSocket(server);

server.listen(config.port, () =>
  console.log(`Secure API running on port ${config.port}`)
);