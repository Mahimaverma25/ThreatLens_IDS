/* ================= NAVIGATION ITEMS ================= */

export const activeNavigationItems = [
  // ===== CORE =====
  {
    group: "Core Monitoring",
    items: [
      { label: "Overview", path: "/overview", shortLabel: "OV", roles: ["admin", "analyst", "viewer", "user"] },
      { label: "Dashboard", path: "/dashboard", shortLabel: "DB", roles: ["admin", "analyst", "viewer", "user"] },
      { label: "Live Monitoring", path: "/live-monitoring", shortLabel: "LM", roles: ["admin", "analyst", "viewer", "user"] },
    ],
  },

  // ===== DATA =====
  {
    group: "Data & Analysis",
    items: [
      { label: "Upload", path: "/upload", shortLabel: "UP", roles: ["admin", "analyst"] },
      { label: "Logs", path: "/logs", shortLabel: "LG", roles: ["admin", "analyst", "viewer", "user"] },
      { label: "Alerts", path: "/alerts", shortLabel: "AL", roles: ["admin", "analyst", "viewer", "user"] },
    ],
  },

  // ===== SECURITY =====
  {
    group: "Security Operations",
    items: [
      { label: "Incidents", path: "/incidents", shortLabel: "IN", roles: ["admin", "analyst"] },
      { label: "Threat Map", path: "/threat-map", shortLabel: "TM", roles: ["admin", "analyst", "viewer", "user"] },
      { label: "Blocked IPs", path: "/blocked-ips", shortLabel: "BI", roles: ["admin", "analyst"] },
    ],
  },

  // ===== ML =====
  {
    group: "ML & Reporting",
    items: [
      { label: "Reports", path: "/reports", shortLabel: "RP", roles: ["admin", "analyst"] },
      { label: "Model Health", path: "/model-health", shortLabel: "MH", roles: ["admin", "analyst"] },
    ],
  },

  // ===== MANAGEMENT =====
  {
    group: "Management",
    items: [
      { label: "Users", path: "/users", shortLabel: "US", roles: ["admin"] },
      { label: "Assets", path: "/assets", shortLabel: "AS", roles: ["admin", "analyst"] },
      { label: "Rules", path: "/rules", shortLabel: "RL", roles: ["admin", "analyst"] },
      { label: "Settings", path: "/settings", shortLabel: "ST", roles: ["admin"] },
    ],
  },
];

/* ================= FLATTENED NAV (IMPORTANT FOR YOUR CURRENT LAYOUT) ================= */

export const flatNavigationItems = activeNavigationItems.flatMap((group) => group.items);

/* ================= FUTURE MODULES ================= */

export const futureModuleItems = [
  "Access Management",
  "Alert Details",
  "Response Playbooks",
  "Threat Intel",
];

/* ================= PAGE META ================= */

const defaultEyebrow = "ThreatLens Security Operations Center";

export const getPageMeta = (pathname = "") => {
  const match = flatNavigationItems.find(
    (item) =>
      pathname === item.path ||
      pathname.startsWith(`${item.path}/`)
  );

  if (match) {
    return {
      label: match.label,
      eyebrow: defaultEyebrow,
    };
  }

  if (pathname === "/login") {
    return {
      label: "Login",
      eyebrow: "ThreatLens Authentication",
    };
  }

  if (pathname === "/register") {
    return {
      label: "Register",
      eyebrow: "ThreatLens Authentication",
    };
  }

  return {
    label: "ThreatLens",
    eyebrow: defaultEyebrow,
  };
};