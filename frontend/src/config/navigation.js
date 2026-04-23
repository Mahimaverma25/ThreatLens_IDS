export const navigationSections = [
  {
    title: "Overview",
    items: [
      { label: "Dashboard", path: "/dashboard", shortLabel: "DB", roles: ["admin", "analyst", "viewer"] },
      { label: "Alerts", path: "/alerts", shortLabel: "AL", roles: ["admin", "analyst", "viewer"] },
      { label: "Logs", path: "/logs", shortLabel: "LG", roles: ["admin", "analyst", "viewer"] },
      { label: "Reports", path: "/reports", shortLabel: "RP", roles: ["admin", "analyst", "viewer"] },
      { label: "Threat Map", path: "/threat-map", shortLabel: "TM", roles: ["admin", "analyst", "viewer"] }
    ]
  },
  {
    title: "Detection",
    items: [
      { label: "Incidents", path: "/incidents", shortLabel: "IN", roles: ["admin", "analyst"] },
      { label: "Assets", path: "/assets", shortLabel: "AS", roles: ["admin"] },
      { label: "Rules", path: "/rules", shortLabel: "RL", roles: ["admin", "analyst", "viewer"] },
      { label: "Threat Intel", path: "/threat-intel", shortLabel: "TI", roles: ["admin"] },
      { label: "Model Health", path: "/model-health", shortLabel: "MH", roles: ["admin", "analyst"] }
    ]
  },
  {
    title: "Operations",
    items: [
      { label: "Response Playbooks", path: "/playbooks", shortLabel: "PB", roles: ["admin"] },
      { label: "Users / API Keys", path: "/access", shortLabel: "UA", roles: ["admin"] }
    ]
  }
];

export const allNavigationItems = navigationSections.flatMap((section) => section.items);

export const getPageMeta = (pathname) => {
  if (pathname.startsWith("/alerts/")) {
    return {
      label: "Alert Details",
      eyebrow: "Incident review / evidence / analyst actions"
    };
  }

  const match = allNavigationItems.find((item) => item.path === pathname);

  if (match) {
    return {
      label: match.label,
      eyebrow: "ThreatLens security operations workspace"
    };
  }

  return {
    label: "ThreatLens",
    eyebrow: "ThreatLens security operations workspace"
  };
};
