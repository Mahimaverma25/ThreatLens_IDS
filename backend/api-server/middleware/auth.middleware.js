const jwt = require("jsonwebtoken");
const config = require("../config/env");
const { normalizeRole } = require("../utils/roles");

const authenticate = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];

    /* ================= JWT AUTH ================= */
    const token = authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access token missing",
      });
    }

    try {
      const decoded = jwt.verify(token, config.jwtSecret, {
        algorithms: ["HS256"],
      });
      const userId = decoded.sub || decoded.id || decoded._id;

      if (!userId) {
        return res.status(401).json({
          success: false,
          message: "Invalid token payload",
        });
      }

      req.user = {
        ...decoded,
        role: normalizeRole(decoded.role),
        sub: userId,
        _id: userId,
      };

      return next();

    } catch (error) {
      console.error("❌ JWT Error:", error.message);

      if (error.name === "TokenExpiredError") {
        return res.status(401).json({
          success: false,
          message: "Token expired",
        });
      }

      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

  } catch (err) {
    console.error("🔥 Auth Middleware Error:", err);

    return res.status(500).json({
      success: false,
      message: "Internal server error in auth middleware",
    });
  }
};

module.exports = authenticate;
