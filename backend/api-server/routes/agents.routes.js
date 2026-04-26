const router = require("express").Router();

const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin, authorizeViewer } = require("../middleware/authorize.middleware");
const { validateAPIKey } = require("../middleware/ingest.middleware");
const { agentLimiter } = require("../middleware/rateLimit");
const asyncHandler = require("../utils/asyncHandler");
const {
  createAgentAsset,
  recordHeartbeat,
  listAgentHeartbeats,
} = require("../controllers/agents.controller");

router.post("/register", authenticate, authorizeAdmin, asyncHandler(createAgentAsset));
router.get("/heartbeats", authenticate, authorizeViewer, asyncHandler(listAgentHeartbeats));
router.post("/heartbeat", agentLimiter, validateAPIKey, asyncHandler(recordHeartbeat));

module.exports = router;
