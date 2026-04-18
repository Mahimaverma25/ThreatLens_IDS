const bcrypt = require("bcryptjs");
const User = require("../models/User");
const RefreshToken = require("../models/RefreshToken");
const AuditLog = require("../models/AuditLog");
const Organization = require("../models/Organization");
const config = require("../config/env");
const { sendVerificationEmail } = require("../services/email.service");

const {
  generateAccessToken,
  generateRefreshToken,
  generateVerificationToken,
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

const getVerificationExpiry = () =>
  new Date(Date.now() + config.emailVerificationExpiryMinutes * 60 * 1000);

const clearVerificationState = (user) => {
  user.emailVerified = true;
  user.emailVerificationTokenHash = null;
  user.emailVerificationExpiresAt = null;
  user.emailVerificationSentAt = null;
};

const issueVerificationForUser = async (user) => {
  const verificationToken = generateVerificationToken();

  user.emailVerified = false;
  user.emailVerificationTokenHash = hashToken(verificationToken);
  user.emailVerificationExpiresAt = getVerificationExpiry();
  user.emailVerificationSentAt = new Date();
  await user.save();

  const verificationUrl = `${config.frontendBaseUrl.replace(/\/+$/, "")}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
  const delivery = await sendVerificationEmail({
    email: user.email,
    username: user.username,
    verificationUrl,
  });

  return {
    verificationUrl,
    delivery,
  };
};

const isVerificationPending = (user) => user.emailVerified === false;

const formatVerificationInstructions = (deliveryMode) =>
  deliveryMode === "preview"
    ? "Registration successful. A development preview link is ready for email verification."
    : "Registration successful. Check your inbox for a verification email to activate your account.";

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
    const baseOrgIdentifier = (orgName || email.split("@")[0])
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

    const org = await Organization.create({
      org_id: orgIdentifier,
      org_name: orgName || username || orgIdentifier,
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

    const user = await User.create({
      email,
      username,
      passwordHash,
      role: ROLE_VIEWER,
      emailVerified: false,
      _org_id: org._id,
    });

    const verification = await issueVerificationForUser(user);

    try {
      await AuditLog.create({
        action: "auth.register",
        userId: user._id,
        _org_id: org._id,
        ip: req.ip,
        success: true,
      });
    } catch (error) {
      console.warn("Audit log failed (ignored)");
    }

    return res.status(201).json({
      message: formatVerificationInstructions(verification.delivery.deliveryMode),
      verificationRequired: true,
      deliveryMode: verification.delivery.deliveryMode,
      email: user.email,
      previewUrl:
        config.nodeEnv === "development" ? verification.delivery.previewUrl : undefined,
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

    const user = await User.findOne({ email }).select(
      "+passwordHash +emailVerificationTokenHash"
    );

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (!user.passwordHash) {
      return res.status(500).json({ message: "Password not set properly" });
    }

    await ensureStoredRole(user);

    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    if (isVerificationPending(user)) {
      return res.status(403).json({
        message: "Your email address is not verified yet. Check your inbox to continue, or request a new verification email.",
        verificationRequired: true,
        email: user.email,
      });
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
    console.error("LOGIN ERROR:", error);
    return res.status(500).json({
      message: "Login failed",
      error: config.nodeEnv === "development" ? error.message : undefined,
    });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();
    const token = req.body?.token?.trim();

    if (!email || !token) {
      return res
        .status(400)
        .json({ message: "Email and verification token are required" });
    }

    const user = await User.findOne({ email }).select("+emailVerificationTokenHash");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!isVerificationPending(user)) {
      return res.json({
        message: "Email already verified. You can sign in now.",
        user: user.toJSON(),
      });
    }

    if (!user.emailVerificationTokenHash || !user.emailVerificationExpiresAt) {
      return res.status(400).json({
        message: "Verification token missing. Request a new verification email.",
      });
    }

    if (user.emailVerificationExpiresAt < new Date()) {
      return res.status(400).json({
        message: "Verification token expired. Request a new verification email.",
      });
    }

    if (hashToken(token) !== user.emailVerificationTokenHash) {
      return res.status(400).json({ message: "Invalid verification token" });
    }

    clearVerificationState(user);
    await user.save();

    return res.json({
      message: "Email verified successfully. You can sign in now.",
      user: user.toJSON(),
    });
  } catch (error) {
    console.error("VERIFY EMAIL ERROR:", error);
    return res.status(500).json({ message: "Email verification failed" });
  }
};

const resendVerification = async (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email }).select("+emailVerificationTokenHash");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!isVerificationPending(user)) {
      return res.json({ message: "Email is already verified. You can sign in now." });
    }

    const verification = await issueVerificationForUser(user);

    return res.json({
      message: "Verification email sent successfully.",
      verificationRequired: true,
      deliveryMode: verification.delivery.deliveryMode,
      email: user.email,
      previewUrl:
        config.nodeEnv === "development" ? verification.delivery.previewUrl : undefined,
    });
  } catch (error) {
    console.error("RESEND VERIFICATION ERROR:", error);
    return res.status(500).json({ message: "Failed to resend verification email" });
  }
};

const me = async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

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
  verifyEmail,
  resendVerification,
  me,
  refresh,
  logout,
};
