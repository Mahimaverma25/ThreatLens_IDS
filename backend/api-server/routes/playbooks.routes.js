const router = require("express").Router();

const authenticate = require("../middleware/auth.middleware");
const { authorizeAnalyst, authorizeViewer } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");
const {
  listPlaybooks,
  executePlaybook,
} = require("../controllers/playbooks.controller");

router.use(authenticate);

router.get("/", authorizeViewer, asyncHandler(listPlaybooks));
router.post("/execute", authorizeAnalyst, asyncHandler(executePlaybook));

module.exports = router;
