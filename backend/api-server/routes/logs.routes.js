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

const ALLOWED_CSV_MIME_TYPES = [
  "text/csv",
  "application/csv",
  "application/vnd.ms-excel",
  "text/plain",
];

const GENERIC_UPLOAD_MIME_TYPES = [
  "application/json",
  "application/x-ndjson",
  "application/octet-stream",
  "text/plain",
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
    filename: (req, file, callback) => {
      callback(null, safeUploadName(file.originalname));
    },
  }),

  limits: {
    fileSize: Number(config.maxUploadFileSizeBytes || 5 * 1024 * 1024),
  },

  fileFilter: (req, file, callback) => {
    const lowerName = String(file.originalname || "").toLowerCase();
    const mimeType = String(file.mimetype || "").toLowerCase();

    const isSupported = SUPPORTED_UPLOAD_EXTENSIONS.some((extension) =>
      lowerName.endsWith(extension)
    );

    if (!isSupported) {
      return callback(
        new Error("Unsupported file type. Allowed: CSV, JSON, NDJSON, LOG, TXT")
      );
    }

    if (lowerName.endsWith(".csv")) {
      const csvMimeOk =
        !mimeType ||
        ALLOWED_CSV_MIME_TYPES.includes(mimeType) ||
        mimeType.includes("csv");

      if (!csvMimeOk) {
        return callback(new Error("Invalid CSV upload type"));
      }

      return callback(null, true);
    }

    const genericMimeOk =
      !mimeType ||
      GENERIC_UPLOAD_MIME_TYPES.includes(mimeType) ||
      mimeType.startsWith("text/");

    if (!genericMimeOk) {
      return callback(new Error("Invalid upload MIME type"));
    }

    return callback(null, true);
  },
});

/**
 * ==============================
 * Agent / HIDS / NIDS ingest route
 * ==============================
 *
 * Used by:
 * - agent/apiClient.js
 * - realtime-agent.js
 * - Snort/NIDS collector
 *
 * Required headers:
 * - x-api-key
 * - x-timestamp
 * - x-nonce
 * - x-asset-id
 * - x-signature
 * - x-signature-version
 */
router.post(
  "/ingest",
  agentLimiter,
  validateAPIKey,
  validateIngestPayload,
  asyncHandler(ingestLogs)
);

/**
 * ==============================
 * JWT protected log routes
 * ==============================
 */

// List logs for dashboard/logs page
router.get("/", authenticate, orgIsolation, authorizeViewer, asyncHandler(listLogs));

// Create manual/admin log
router.post("/", authenticate, orgIsolation, authorizeAdmin, asyncHandler(createLog));

// Upload CSV/JSON/NDJSON/LOG/TXT logs
router.post(
  "/upload",
  authenticate,
  orgIsolation,
  authorizeAdmin,
  upload.single("file"),
  asyncHandler(uploadLogs)
);

module.exports = router;