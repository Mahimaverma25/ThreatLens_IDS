const bcrypt = require("bcryptjs");

const User = require("../models/User");
const { normalizeRole } = require("../utils/roles");

const DEFAULT_SETTINGS = {
  system: {
    theme: "dark",
    notifications: true,
  },
  idsConfig: {
    alertThreshold: 70,
    autoBlock: false,
  },
  agentApi: {
    endpoint: "",
    apiKey: "",
  },
};

const buildSettingsPayload = (user) => ({
  profile: {
    name: user.username || "",
    email: user.email || "",
  },
  system: {
    ...DEFAULT_SETTINGS.system,
    ...(user.settings?.system || {}),
  },
  idsConfig: {
    ...DEFAULT_SETTINGS.idsConfig,
    ...(user.settings?.idsConfig || {}),
  },
  agentApi: {
    ...DEFAULT_SETTINGS.agentApi,
    ...(user.settings?.agentApi || {}),
  },
  user: user.toJSON(),
});

const getSettings = async (req, res) => {
  const user = await User.findOne({ _id: req.user.sub, _org_id: req.orgId });

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  if (user.role !== normalizeRole(user.role)) {
    user.role = normalizeRole(user.role);
    await user.save();
  }

  return res.json({ data: buildSettingsPayload(user) });
};

const updateSettings = async (req, res) => {
  const user = await User.findOne({ _id: req.user.sub, _org_id: req.orgId }).select("+passwordHash");

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const {
    profile = {},
    password = {},
    system = {},
    idsConfig = {},
    agentApi = {},
  } = req.body || {};

  const nextName =
    typeof profile.name === "string" ? profile.name.trim() : user.username || "";
  const nextEmail =
    typeof profile.email === "string"
      ? profile.email.trim().toLowerCase()
      : user.email;

  if (nextEmail !== user.email) {
    const existingUser = await User.findOne({
      email: nextEmail,
      _id: { $ne: user._id },
    }).select("_id");

    if (existingUser) {
      return res.status(409).json({ message: "Email already in use" });
    }
  }

  if (password.newPass) {
    if (!password.current) {
      return res.status(400).json({
        message: "Current password is required to set a new password",
      });
    }

    const isMatch = await bcrypt.compare(String(password.current), user.passwordHash || "");
    if (!isMatch) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    user.passwordHash = await bcrypt.hash(String(password.newPass), 12);
  }

  const nextAlertThreshold = Number(idsConfig.alertThreshold);

  user.username = nextName;
  user.email = nextEmail;
  user.role = normalizeRole(user.role);
  user.settings = {
    system: {
      ...DEFAULT_SETTINGS.system,
      ...(user.settings?.system || {}),
      ...(system || {}),
      notifications:
        typeof system.notifications === "boolean"
          ? system.notifications
          : user.settings?.system?.notifications ?? DEFAULT_SETTINGS.system.notifications,
    },
    idsConfig: {
      ...DEFAULT_SETTINGS.idsConfig,
      ...(user.settings?.idsConfig || {}),
      ...(idsConfig || {}),
      alertThreshold: Number.isFinite(nextAlertThreshold)
        ? Math.max(0, Math.min(100, nextAlertThreshold))
        : Number(user.settings?.idsConfig?.alertThreshold ?? DEFAULT_SETTINGS.idsConfig.alertThreshold),
      autoBlock:
        typeof idsConfig.autoBlock === "boolean"
          ? idsConfig.autoBlock
          : user.settings?.idsConfig?.autoBlock ?? DEFAULT_SETTINGS.idsConfig.autoBlock,
    },
    agentApi: {
      ...DEFAULT_SETTINGS.agentApi,
      ...(user.settings?.agentApi || {}),
      endpoint:
        typeof agentApi.endpoint === "string"
          ? agentApi.endpoint.trim()
          : user.settings?.agentApi?.endpoint ?? DEFAULT_SETTINGS.agentApi.endpoint,
      apiKey:
        typeof agentApi.apiKey === "string"
          ? agentApi.apiKey.trim()
          : user.settings?.agentApi?.apiKey ?? DEFAULT_SETTINGS.agentApi.apiKey,
    },
  };

  await user.save();

  return res.json({
    message: "Settings updated successfully",
    data: buildSettingsPayload(user),
  });
};

module.exports = {
  getSettings,
  updateSettings,
};
