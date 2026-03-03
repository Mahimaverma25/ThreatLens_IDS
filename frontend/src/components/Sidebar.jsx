import { Link, useLocation } from "react-router-dom";

const Sidebar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path ? "active" : "";

  return (
    <div className="sidebar">
      <h3>Menu</h3>
      <ul>
        <li>
          <Link to="/" className={isActive("/")}>
            📊 Dashboard
          </Link>
        </li>
        <li>
          <Link to="/alerts" className={isActive("/alerts")}>
            🚨 Alerts
          </Link>
        </li>
        <li>
          <Link to="/logs" className={isActive("/logs")}>
            📜 Logs
          </Link>
        </li>
      </ul>
    </div>
  );
};

export default Sidebar;
