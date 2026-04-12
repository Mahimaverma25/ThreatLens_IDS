import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { navigationSections } from "../config/navigation";

const AppSidebar = () => {
  const location = useLocation();
  const { user } = useAuth();
  const role = user?.role || "viewer";

  const isActive = (path) =>
    location.pathname === path || location.pathname.startsWith(`${path}/`) ? "active" : "";

  return (
    <div className="sidebar">
      <div className="sidebar-top">
        <div className="sidebar-title">Command Menu</div>
        <p>Navigation and module access for the SOC workflow.</p>
      </div>

      {navigationSections.map((section) => {
        const items = section.items.filter((item) => item.roles.includes(role));

        if (items.length === 0) {
          return null;
        }

        return (
          <div key={section.title} className="sidebar-group">
            <h3>{section.title}</h3>
            <ul>
              {items.map((item) => (
                <li key={item.path}>
                  <Link to={item.path} className={isActive(item.path)}>
                    <span className="nav-chip">{item.shortLabel}</span>
                    <span>{item.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
};

export default AppSidebar;
