const router = require("express").Router();
const fs = require("fs");
const multer = require("multer");
const os = require("os");
const path = require("path");

const {
  validateAPIKey,
  validateIngestPayload,
} = require("../middleware/ingest.middleware");

const authenticate = require("../middleware/auth.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const {
  authorizeAdmin,
  authorizeViewer,
} = require("../middleware/authorize.middleware");

const { agentLimiter } = require("../middleware/rateLimit");
const asyncHandler = require("../utils/asyncHandler");
const config = require("../config/env");

const {
  listLogs,
  createLog,
  ingestLogs,
  uploadLogs,
} = require("../controllers/logs.controller");

const SUPPORTED_UPLOAD_EXTENSIONS = [".csv", ".json", ".log", ".txt", ".ndjson"];

const ALLOWED_MIME_TYPES = [
  "text/csv",
  "application/csv",
  "application/vnd.ms-excel",
  "text/plain",
  "application/json",
  "application/x-ndjson",
  "application/octet-stream",
];

const uploadDir = path.join(os.tmpdir(), "threatlens-uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const safeUploadName = (originalName = "upload") => {
  const baseName = path.basename(String(originalName || "upload"));
  return `${Date.now()}-${baseName.replace(/[^\w.\-]/g, "_")}`;
};

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, callback) => callback(null, uploadDir),
    filename: (req, file, callback) => callback(null, safeUploadName(file.originalname)),
  }),

  limits: {
    fileSize: Number(config.maxUploadFileSizeBytes || 5 * 1024 * 1024),
  },

  fileFilter: (req, file, callback) => {
    const lowerName = String(file.originalname || "").toLowerCase();
    const mimeType = String(file.mimetype || "").toLowerCase();

    const hasValidExtension = SUPPORTED_UPLOAD_EXTENSIONS.some((extension) =>
      lowerName.endsWith(extension)
    );

    const hasValidMime =
      !mimeType ||
      ALLOWED_MIME_TYPES.includes(mimeType) ||
      mimeType.startsWith("text/") ||
      mimeType.includes("csv") ||
      mimeType.includes("json");

    if (!hasValidExtension) {
      return callback(
        new Error("Unsupported file type. Allowed: CSV, JSON, NDJSON, LOG, TXT")
      );
    }

    if (!hasValidMime) {
      return callback(new Error("Invalid upload MIME type"));
    }

    return callback(null, true);
  },
});

const handleUpload = (req, res, next) => {
  upload.single("file")(req, res, (error) => {
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.message || "File upload failed",
      });
    }

    return next();
  });
};

/**
 * Agent / HIDS / NIDS ingest route
 *
 * Final URL:
 * POST /api/logs/ingest
 *
 * Used by:
 * - backend/agent/services/apiClient.js
 * - HIDS agent
 * - Snort/NIDS collector
 */
router.post(
  "/ingest",
  agentLimiter,
  validateAPIKey,
  validateIngestPayload,
  asyncHandler(ingestLogs)
);

/**
 * JWT protected dashboard/log routes
 */

// List logs for Logs page / Dashboard
router.get(
  "/",
  authenticate,
  orgIsolation,
  authorizeViewer,
  asyncHandler(listLogs)
);

// Create manual/admin log
router.post(
  "/",
  authenticate,
  orgIsolation,
  authorizeAdmin,
  asyncHandler(createLog)
);

// Upload CSV/JSON/NDJSON/LOG/TXT logs
router.post(
  "/upload",
  authenticate,
  orgIsolation,
  authorizeAdmin,
  handleUpload,
  asyncHandler(uploadLogs)
);

/**
 * Manual test route for demo/admin testing
 * Final URL:
 * POST /api/logs/simulate
 */
router.post(
  "/simulate",
  authenticate,
  orgIsolation,
  authorizeAdmin,
  asyncHandler(async (req, res) => {
    const fakeLog = {
      eventType: "brute_force_attempt",
      source: "manual-simulation",
      ip: "192.168.1.50",
      severity: "high",
      message: "Simulated brute force SSH attempt detected",
      assetId: req.body.assetId || "demo-asset",
      metadata: {
        failedAttempts: 12,
        destinationPort: 22,
        protocol: "TCP",
        simulated: true,
      },
    };

    req.body = { logs: [fakeLog] };

    return ingestLogs(req, res);
  })
);

module.exports = router;