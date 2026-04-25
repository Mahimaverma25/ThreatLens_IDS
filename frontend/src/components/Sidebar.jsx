import { Link, useLocation } from "react-router-dom";

const Sidebar = () => {
  const location = useLocation();

  const isActive = (path) =>
    location.pathname === path || location.pathname.startsWith(path)
      ? "active"
      : "";

  const menu = [
    {
      title: "Core",
      items: [
        { label: "Overview", path: "/overview", icon: "🧠" },
        { label: "Dashboard", path: "/dashboard", icon: "📊" },
        { label: "Live Monitoring", path: "/live-monitoring", icon: "📡" },
      ],
    },
    {
      title: "Data",
      items: [
        { label: "Upload", path: "/upload", icon: "📤" },
        { label: "Logs", path: "/logs", icon: "📜" },
        { label: "Alerts", path: "/alerts", icon: "🚨" },
      ],
    },
    {
      title: "Security",
      items: [
        { label: "Incidents", path: "/incidents", icon: "⚠️" },
        { label: "Threat Map", path: "/threat-map", icon: "🌍" },
        { label: "Blocked IPs", path: "/blocked-ips", icon: "⛔" },
      ],
    },
    {
      title: "ML & Reports",
      items: [
        { label: "Reports", path: "/reports", icon: "📑" },
        { label: "Model Health", path: "/model-health", icon: "🤖" },
      ],
    },
    {
      title: "Management",
      items: [
        { label: "Users", path: "/users", icon: "👥" },
        { label: "Assets", path: "/assets", icon: "🖥️" },
        { label: "Rules", path: "/rules", icon: "⚙️" },
        { label: "Settings", path: "/settings", icon: "🔧" },
      ],
    },
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <h2>🛡️ ThreatLens</h2>
      </div>

      {menu.map((group) => (
        <div key={group.title} className="sidebar-group">
          <p className="sidebar-title">{group.title}</p>

          <ul>
            {group.items.map((item) => (
              <li key={item.path}>
                <Link to={item.path} className={isActive(item.path)}>
                  <span className="icon">{item.icon}</span>
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
};

export default Sidebar;