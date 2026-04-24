export const activeNavigationItems = [
  { label: "Dashboard", path: "/dashboard", shortLabel: "DB", roles: ["admin", "analyst", "viewer"] },
  { label: "Overview", path: "/overview", shortLabel: "OV", roles: ["admin", "analyst", "viewer"] },
  { label: "Upload", path: "/upload", shortLabel: "UP", roles: ["admin", "analyst", "viewer"] },
  { label: "Live Monitoring", path: "/live-monitoring", shortLabel: "LM", roles: ["admin", "analyst", "viewer"] },
  { label: "Alerts", path: "/alerts", shortLabel: "AL", roles: ["admin", "analyst", "viewer"] },
  { label: "Logs", path: "/logs", shortLabel: "LG", roles: ["admin", "analyst", "user", "viewer"] },
  { label: "Reports", path: "/reports", shortLabel: "RP", roles: ["admin", "analyst", "viewer"] },
  { label: "Model Health", path: "/model-health", shortLabel: "MH", roles: ["admin", "analyst"] },
];

export const futureModuleItems = [
  "Access",
  "Access Management",
  "Alert Details",
  "Assets",
  "Blocked IPs",
  "Incidents",
  "Response Playbooks",
  "Rules",
  "Threat Intel",
  "Threat Map",
  "Users",
];

const defaultEyebrow = "ThreatLens security operations workspace";

export const getPageMeta = (pathname) => {
  const match = activeNavigationItems.find((item) => item.path === pathname);

  if (match) {
    return {
      label: match.label,
      eyebrow: defaultEyebrow,
    };
  }

  if (pathname === "/login") {
    return {
      label: "Login",
      eyebrow: "ThreatLens authentication",
    };
  }

  if (pathname === "/register") {
    return {
      label: "Register",
      eyebrow: "ThreatLens authentication",
    };
  }

  return {
    label: "ThreatLens",
    eyebrow: defaultEyebrow,
  };
};
