const jwt = require("jsonwebtoken");
const config = require("../config/env");

/**
 * Authentication Middleware
 * Supports:
 * 1. API Key (agents)
 * 2. JWT (users)
 */
const authenticate = (req, res, next) => {
  try {
    const apiKey = req.headers["x-api-key"];
    const authHeader = req.headers["authorization"];

    /* ================= API KEY AUTH ================= */
    if (apiKey) {
      if (apiKey === config.apiKey) {
        req.user = {
          type: "agent",
          role: "system",
        };
        return next();
      }

      console.warn("❌ Invalid API Key");
      return res.status(401).json({
        success: false,
        message: "Invalid API key",
      });
    }

    /* ================= JWT AUTH ================= */
    let token = null;

    // ✅ Extract token safely
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access token missing",
      });
    }

    try {
      const decoded = jwt.verify(token, config.jwtSecret);

      // ✅ Normalize user structure
      req.user = {
        ...decoded,
        sub: decoded.sub || decoded.id || decoded._id,
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