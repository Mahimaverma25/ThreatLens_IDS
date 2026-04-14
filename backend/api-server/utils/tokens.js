const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const config = require("../config/env");
const { normalizeRole } = require("./roles");

const generateAccessToken = (user) =>
  jwt.sign(
    { sub: user.id, role: normalizeRole(user.role), email: user.email },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );

const generateRefreshToken = () =>
  crypto.randomBytes(64).toString("hex");

const generateVerificationToken = () =>
  crypto.randomBytes(32).toString("hex");

const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");

const getRefreshTokenExpiry = () => {
  const now = new Date();
  const days = Number.parseInt(config.refreshTokenExpiresIn.replace(/[^0-9]/g, ""), 10);
  if (Number.isNaN(days)) {
    return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  }
  return new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  generateVerificationToken,
  hashToken,
  getRefreshTokenExpiry
};
