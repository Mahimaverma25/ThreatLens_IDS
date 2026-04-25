const router = require("express").Router();
const multer = require("multer");
const { validateAPIKey, validateIngestPayload } = require("../middleware/ingest.middleware");
const authenticate = require("../middleware/auth.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const { authorizeAdmin, authorizeViewer } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");

const {
  listLogs,
  createLog,
  ingestLogs,
  uploadLogs
} = require("../controllers/logs.controller");

const SUPPORTED_UPLOAD_EXTENSIONS = [".csv", ".json", ".log", ".txt", ".ndjson"];
const MAX_UPLOAD_FILE_SIZE = 100 * 1024 * 1024;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_FILE_SIZE },
  fileFilter: (req, file, callback) => {
    const lowerName = String(file.originalname || "").toLowerCase();
    const isSupported = SUPPORTED_UPLOAD_EXTENSIONS.some((extension) =>
      lowerName.endsWith(extension)
    );

    if (!isSupported) {
      return callback(
        new Error("Unsupported file type. Allowed: CSV, JSON, NDJSON, LOG, TXT")
      );
    }

    return callback(null, true);
  }
});

/**
 * ==============================
 * 🤖 AGENT ROUTE (API KEY BASED)
 * ==============================
 * Validates API key with HMAC signature
 * Validates payload structure
 * Routes to org isolation context
 */
router.post(
  "/ingest",
  validateAPIKey,
  validateIngestPayload,
  asyncHandler(ingestLogs)
);

/**
 * ==============================
 * 👤 USER ROUTES (JWT BASED)
 * ==============================
 */

// Get logs
router.get("/", authenticate, orgIsolation, authorizeViewer, asyncHandler(listLogs));

// Create log manually
router.post("/", authenticate, orgIsolation, authorizeAdmin, asyncHandler(createLog));

// Upload logs file
router.post(
  "/upload",
  authenticate,
  orgIsolation,
  authorizeAdmin,
  upload.single("file"),
  asyncHandler(uploadLogs)
);

module.exports = router;
