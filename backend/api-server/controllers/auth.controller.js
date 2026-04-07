const bcrypt = require("bcryptjs");
const User = require("../models/User");
const RefreshToken = require("../models/RefreshToken");
const AuditLog = require("../models/AuditLog");
const Organization = require("../models/Organization");
const config = require("../config/env");
const {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  getRefreshTokenExpiry,
} = require("../utils/tokens");

/* ================= COOKIE HELPERS ================= */

const setRefreshCookie = (res, token, expiresAt) => {
  res.cookie(config.refreshCookieName, token, {
    httpOnly: true,
    secure: config.refreshCookieSecure,
    sameSite: config.refreshCookieSameSite,
    expires: expiresAt,
  });
};

const clearRefreshCookie = (res) => {
  res.clearCookie(config.refreshCookieName, {
    httpOnly: true,
    secure: config.refreshCookieSecure,
    sameSite: config.refreshCookieSameSite,
  });
};

/* ================= REGISTER ================= */

const register = async (req, res) => {
  try {
    console.log("📥 REGISTER BODY:", req.body);

    let { email, password, username, orgName } = req.body || {};

    // 🔥 SAFE CHECK
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    email = email.trim().toLowerCase();
    password = password.trim();

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const orgIdentifier = orgName || email.split("@")[0];

    const org = await Organization.create({
      org_id: orgIdentifier.toLowerCase(),
      org_name: orgName || username || orgIdentifier,
      org_plan: "starter",
      status: "active",
      ingest_quota_per_minute: 1000,
      ingest_quota_per_day: 100000,
      feature_flags: {
        real_time_alerts: true,
        correlation_engine: true,
        anomaly_detection: false,
        threat_intel: false,
      },
      data_retention_days: 30,
    });

    const user = await User.create({
      email,
      username,
      passwordHash,
      role: "admin",
      _org_id: org._id,
    });

    await AuditLog.create({
      action: "auth.register",
      userId: user._id,
      _org_id: org._id,
      ip: req.ip,
      success: true,
    });

    return res.status(201).json({
      message: "Registration successful",
      user: user.toJSON(),
    });
  } catch (error) {
    console.error("❌ REGISTER ERROR:", error);
    return res.status(500).json({
      message: "Registration failed",
      error: config.nodeEnv === "development" ? error.message : undefined,
    });
  }
};

/* ================= LOGIN ================= */

const login = async (req, res) => {
  try {
    console.log("📥 LOGIN BODY:", req.body); // 🔥 DEBUG

    let { email, password } = req.body || {};

    // 🔥 HANDLE EMPTY BODY
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    email = email.trim().toLowerCase();
    password = password.trim();

    const user = await User.findOne({ email }).select("+passwordHash");

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (!user.passwordHash) {
      return res.status(500).json({ message: "Password not set properly" });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken();
    const expiresAt = getRefreshTokenExpiry();

    await RefreshToken.create({
      userId: user._id,
      _org_id: user._org_id,
      tokenHash: hashToken(refreshToken),
      expiresAt,
    });

    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;
    await user.save();

    setRefreshCookie(res, refreshToken, expiresAt);

    return res.status(200).json({
      message: "Login successful",
      token: accessToken,
      user: user.toJSON(),
    });

  } catch (error) {
    console.error("❌ LOGIN ERROR:", error);

    return res.status(500).json({
      message: "Login failed",
      error: config.nodeEnv === "development" ? error.message : undefined,
    });
  }
};

/* ================= ME ================= */

const me = async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({ user: user.toJSON() });

  } catch (error) {
    console.error("❌ ME ERROR:", error);
    return res.status(500).json({ message: "Failed to load user" });
  }
};

/* ================= REFRESH ================= */

const refresh = async (req, res) => {
  try {
    const token = req.cookies?.[config.refreshCookieName];

    if (!token) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    const tokenHash = hashToken(token);

    const stored = await RefreshToken.findOne({
      tokenHash,
      revokedAt: { $exists: false },
    });

    if (!stored || stored.expiresAt < new Date()) {
      return res.status(401).json({ message: "Refresh token invalid" });
    }

    const user = await User.findById(stored.userId);

    if (!user) {
      return res.status(401).json({ message: "Invalid user" });
    }

    const newRefresh = generateRefreshToken();
    const newExpiry = getRefreshTokenExpiry();

    stored.revokedAt = new Date();
    stored.replacedByTokenHash = hashToken(newRefresh);
    await stored.save();

    await RefreshToken.create({
      userId: user._id,
      _org_id: user._org_id,
      tokenHash: hashToken(newRefresh),
      expiresAt: newExpiry,
    });

    setRefreshCookie(res, newRefresh, newExpiry);

    return res.json({
      token: generateAccessToken(user),
    });

  } catch (error) {
    console.error("❌ REFRESH ERROR:", error);
    return res.status(500).json({ message: "Refresh failed" });
  }
};

/* ================= LOGOUT ================= */

const logout = async (req, res) => {
  try {
    const token = req.cookies?.[config.refreshCookieName];

    if (token) {
      await RefreshToken.updateOne(
        { tokenHash: hashToken(token) },
        { $set: { revokedAt: new Date() } }
      );
    }

    clearRefreshCookie(res);

    return res.json({ message: "Logged out" });

  } catch (error) {
    console.error("❌ LOGOUT ERROR:", error);
    return res.status(500).json({ message: "Logout failed" });
  }
};

module.exports = { register, login, me, refresh, logout };