const router = require("express").Router();
const multer = require("multer");
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const { listLogs, createLog, ingestLogs, uploadLogs, simulateTraffic } = require("../controllers/logs.controller");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

// All routes except /ingest require org isolation
router.get("/", authenticate, orgIsolation, listLogs);
router.post("/", authenticate, orgIsolation, createLog);
router.post("/ingest", ingestLogs);
router.post("/upload", authenticate, orgIsolation, authorize(["admin", "analyst"]), upload.single("file"), uploadLogs);
router.post("/simulate", authenticate, orgIsolation, authorize(["admin", "analyst"]), simulateTraffic);

module.exports = router;
