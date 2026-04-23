const router = require("express").Router();

const authenticate = require("../middleware/auth.middleware");
const { authorizeAdmin, authorizeViewer } = require("../middleware/authorize.middleware");
const asyncHandler = require("../utils/asyncHandler");
const {
  listRules,
  createRule,
  updateRule,
  deleteRule,
} = require("../controllers/rules.controller");

router.use(authenticate);

router.get("/", authorizeViewer, asyncHandler(listRules));
router.post("/", authorizeAdmin, asyncHandler(createRule));
router.patch("/:id", authorizeAdmin, asyncHandler(updateRule));
router.delete("/:id", authorizeAdmin, asyncHandler(deleteRule));

module.exports = router;
