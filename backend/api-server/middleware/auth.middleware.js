const jwt = require("jsonwebtoken");
const config = require("../config/env");

/**
 * Authentication Middleware
 * Supports:
 * 1. API Key (for agents / ingestion)
 * 2. JWT Token (for frontend users)
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
      } else {
        console.warn("❌ Invalid API Key");
        return res.status(401).json({
          success: false,
          message: "Invalid API key",
        });
      }
    }

    /* ================= JWT AUTH ================= */
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.split(" ")[1]; // safer split

      if (!token) {
        return res.status(401).json({
          success: false,
          message: "Token missing",
        });
      }

      try {
        const decoded = jwt.verify(token, config.jwtSecret);

        // ✅ Attach user info
        req.user = decoded;

        return next();
      } catch (error) {
        console.error("❌ JWT Error:", error.message);

        // Handle specific JWT errors
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
    }

    /* ================= NO AUTH PROVIDED ================= */
    return res.status(401).json({
      success: false,
      message: "Unauthorized access",
    });

  } catch (err) {
    console.error("🔥 Auth Middleware Error:", err.message);

    return res.status(500).json({
      success: false,
      message: "Internal server error in auth middleware",
    });
  }
};

module.exports = authenticate;