const bcrypt = require("bcryptjs");
const User = require("../models/User");
const RefreshToken = require("../models/RefreshToken");
const AuditLog = require("../models/AuditLog");
const Organization = require("../models/Organization");
const APIKey = require("../models/APIKey");
const Log = require("../models/Log");
const Alert = require("../models/Alerts");
const config = require("../config/env");

const {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  getRefreshTokenExpiry,
} = require("../utils/tokens");
const { normalizeRole, ROLE_VIEWER } = require("../utils/roles");

const ensureStoredRole = async (user) => {
  const normalizedRole = normalizeRole(user.role);

  if (user.role !== normalizedRole) {
    user.role = normalizedRole;
    await user.save();
  }

  return user;
};

const createAuditLogSafe = async (payload) => {
  try {
    await AuditLog.create(payload);
  } catch (error) {
    console.warn("Audit log failed (ignored)");
  }
};

const setRefreshCookie = (res, token, expiresAt) => {
  res.cookie(config.refreshCookieName, token, {
    httpOnly: true,
    secure: config.refreshCookieSecure,
    sameSite: config.refreshCookieSameSite,
    domain: config.refreshCookieDomain,
    path: "/",
    expires: expiresAt,
  });
};

const clearRefreshCookie = (res) => {
  res.clearCookie(config.refreshCookieName, {
    httpOnly: true,
    secure: config.refreshCookieSecure,
    sameSite: config.refreshCookieSameSite,
    domain: config.refreshCookieDomain,
    path: "/",
  });
};

const findPrimaryOrganization = async () => {
  const adminUser = await User.findOne({ role: "admin", _org_id: { $ne: null } })
    .sort({ createdAt: 1 })
    .select("_org_id");

  if (adminUser?._org_id) {
    return Organization.findById(adminUser._org_id);
  }

  const activeKey = await APIKey.findOne({ is_active: true })
    .sort({ usage_count: -1, last_used_at: -1, created_at: -1 })
    .select("_org_id");

  if (activeKey?._org_id) {
    return Organization.findById(activeKey._org_id);
  }

  return null;
};

const buildOrgIdentifier = async (seedValue) => {
  const baseOrgIdentifier = String(seedValue || "org")
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 32) || "org";

  let orgIdentifier = baseOrgIdentifier;
  let suffix = 1;

  while (await Organization.exists({ org_id: orgIdentifier })) {
    orgIdentifier = `${baseOrgIdentifier}-${suffix++}`;
  }

  return orgIdentifier;
};

const resolveOrganizationForRegistration = async ({ email, username, orgName }) => {
  if (orgName?.trim()) {
    const orgIdentifier = await buildOrgIdentifier(orgName);

    return Organization.create({
      org_id: orgIdentifier,
      org_name: orgName.trim(),
      org_plan: "starter",
      status: "active",
      ingest_quota_per_minute: 1000,
      ingest_quota_per_day: 100000,
      features_enabled: {
        anomaly_detection: false,
        correlation_engine: true,
        threat_intel_enrichment: false,
        custom_rules: false,
      },
      data_retention_days: 30,
    });
  }

  const primaryOrg = await findPrimaryOrganization();
  if (primaryOrg) {
    return primaryOrg;
  }

  const orgIdentifier = await buildOrgIdentifier(email.split("@")[0]);

  return Organization.create({
    org_id: orgIdentifier,
    org_name: username || orgIdentifier,
    org_plan: "starter",
    status: "active",
    ingest_quota_per_minute: 1000,
    ingest_quota_per_day: 100000,
    features_enabled: {
      anomaly_detection: false,
      correlation_engine: true,
      threat_intel_enrichment: false,
      custom_rules: false,
    },
    data_retention_days: 30,
  });
};

const maybeRelinkViewerToPrimaryOrg = async (user) => {
  if (!user || user.role === "admin" || !user._org_id) {
    return user;
  }

  const primaryOrg = await findPrimaryOrganization();
  if (!primaryOrg || primaryOrg._id.toString() === user._org_id.toString()) {
    return user;
  }

  const [currentAlertCount, currentTelemetryCount] = await Promise.all([
    Alert.countDocuments({ _org_id: user._org_id }),
    Log.countDocuments({
      _org_id: user._org_id,
      source: { $in: ["snort", "agent", "ids-engine", "simulator", "upload"] },
    }),
  ]);

  if (currentAlertCount === 0 && currentTelemetryCount === 0) {
    user._org_id = primaryOrg._id;
    await user.save();
  }

  return user;
};

const register = async (req, res) => {
  try {
    let { email, password, username, orgName } = req.body || {};

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
    const org = await resolveOrganizationForRegistration({ email, username, orgName });

    const user = await User.create({
      email,
      username,
      passwordHash,
      role: ROLE_VIEWER,
      _org_id: org._id,
    });

    await createAuditLogSafe({
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
    console.error("REGISTER ERROR:", error);
    return res.status(500).json({
      message: "Registration failed",
      error: config.nodeEnv === "development" ? error.message : undefined,
    });
  }
};

const login = async (req, res) => {
  try {
    let { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    email = email.trim().toLowerCase();
    password = password.trim();

    const user = await User.findOne({ email }).select("+passwordHash");

    if (!user) {
      await createAuditLogSafe({
        action: "auth.login",
        ip: req.ip,
        success: false,
        metadata: {
          email,
          reason: "user_not_found",
        },
      });
      return res.status(401).json({ message: "User not found" });
    }

    if (!user.passwordHash) {
      return res.status(500).json({ message: "Password not set properly" });
    }

    await maybeRelinkViewerToPrimaryOrg(user);
    await ensureStoredRole(user);

    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
      await createAuditLogSafe({
        action: "auth.login",
        userId: user._id,
        _org_id: user._org_id,
        ip: req.ip,
        success: false,
        metadata: {
          reason: "invalid_password",
        },
      });
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

    await createAuditLogSafe({
      action: "auth.login",
      userId: user._id,
      _org_id: user._org_id,
      ip: req.ip,
      success: true,
    });

    setRefreshCookie(res, refreshToken, expiresAt);

    return res.status(200).json({
      message: "Login successful",
      token: accessToken,
      user: user.toJSON(),
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    return res.status(500).json({
      message: "Login failed",
      error: config.nodeEnv === "development" ? error.message : undefined,
    });
  }
};

const me = async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    await maybeRelinkViewerToPrimaryOrg(user);
    await ensureStoredRole(user);
    return res.json({ user: user.toJSON() });
  } catch (error) {
    console.error("ME ERROR:", error);
    return res.status(500).json({ message: "Failed to load user" });
  }
};

const refresh = async (req, res) => {
  try {
    const token = req.cookies?.[config.refreshCookieName];

    if (!token) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    const tokenHash = hashToken(token);
    const stored = await RefreshToken.findOne({
      tokenHash,
      revokedAt: null,
    });

    if (!stored) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: "Refresh token invalid" });
    }

    if (stored.expiresAt < new Date()) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: "Refresh token expired" });
    }

    const user = await User.findById(stored.userId);

    if (!user) {
      clearRefreshCookie(res);
      return res.status(401).json({ message: "Invalid user" });
    }

    await maybeRelinkViewerToPrimaryOrg(user);
    await ensureStoredRole(user);

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
      revokedAt: null,
    });

    setRefreshCookie(res, newRefresh, newExpiry);

    return res.json({
      token: generateAccessToken(user),
    });
  } catch (error) {
    console.error("REFRESH ERROR:", error);
    return res.status(500).json({ message: "Refresh failed" });
  }
};

const logout = async (req, res) => {
  try {
    const token = req.cookies?.[config.refreshCookieName];

    if (token) {
      const tokenHash = hashToken(token);

      await RefreshToken.updateOne(
        { tokenHash, revokedAt: null },
        { $set: { revokedAt: new Date() } }
      );
    }

    clearRefreshCookie(res);
    return res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("LOGOUT ERROR:", error);
    return res.status(500).json({ message: "Logout failed" });
  }
};

module.exports = {
  register,
  login,
  me,
  refresh,
  logout,
};
