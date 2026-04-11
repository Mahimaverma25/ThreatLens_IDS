import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getPageMeta } from "../config/navigation";

const AppNavbar = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const pageMeta = getPageMeta(location.pathname);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="navbar">
      <div className="navbar-left">
        <div className="brand-mark">TL</div>
        <div>
          <div className="navbar-eyebrow">{pageMeta.eyebrow}</div>
          <h1>ThreatLens</h1>
        </div>
      </div>
      <div className="navbar-right">
        <div className="navbar-panel">
          <span className="panel-label">Workspace</span>
          <strong>{pageMeta.label}</strong>
        </div>
        {user && (
          <>
            <div className="navbar-panel">
              <span className="panel-label">Account</span>
              <strong>{user.email}</strong>
              <span className="user-role">{user.role}</span>
            </div>
            <button onClick={handleLogout} className="logout-btn">
              Logout
            </button>
          </>
        )}
      </div>
    </div>
  );
};

export default AppNavbar;
