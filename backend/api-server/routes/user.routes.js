const router = require("express").Router();
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/authorize.middleware");
const { orgIsolation } = require("../middleware/orgIsolation.middleware");
const asyncHandler = require("../utils/asyncHandler");
const { me, listUsers } = require("../controllers/user.controller");

router.get("/me", authenticate, orgIsolation, asyncHandler(me));
router.get("/", authenticate, orgIsolation, authorize(["admin"]), asyncHandler(listUsers));

module.exports = router;
