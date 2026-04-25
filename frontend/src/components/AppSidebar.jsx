import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { navigationSections } from "../config/navigation";

const normalizeRole = (role) => {
  if (!role) return "viewer";
  const r = String(role).toLowerCase().trim();
  return r === "user" ? "analyst" : r; // keep consistent with App.js
};

const AppSidebar = () => {
  const location = useLocation();
  const { user } = useAuth();

  const role = normalizeRole(user?.role);

  const isActive = (path) =>
    location.pathname === path || location.pathname.startsWith(`${path}/`)
      ? "active"
      : "";

  return (
    <aside className="sidebar">
      {/* ===== HEADER ===== */}
      <div className="sidebar-top">
        <div className="sidebar-brand">
          <span className="brand-logo">TL</span>
          <div>
            <strong>ThreatLens</strong>
            <span>Hybrid IDS</span>
          </div>
        </div>

        <p className="sidebar-desc">
          Security Operations Center Navigation
        </p>
      </div>

      {/* ===== NAVIGATION ===== */}
      <nav className="sidebar-nav">
        {navigationSections.map((section) => {
          const items = section.items.filter(
            (item) =>
              !item.roles || item.roles.includes(role)
          );

          if (!items.length) return null;

          return (
            <div key={section.title} className="sidebar-group">
              <div className="sidebar-group-title">{section.title}</div>

              <ul>
                {items.map((item) => (
                  <li key={item.path}>
                    <Link
                      to={item.path}
                      className={`sidebar-link ${isActive(item.path)}`}
                    >
                      <span className="nav-chip">{item.shortLabel}</span>
                      <span className="nav-label">{item.label}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </nav>

      {/* ===== FOOTER ===== */}
      <div className="sidebar-footer">
        <span>Logged in as</span>
        <strong>{role.toUpperCase()}</strong>
      </div>
    </aside>
  );
};

export default AppSidebar;