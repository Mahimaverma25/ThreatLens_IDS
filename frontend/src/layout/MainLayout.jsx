import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { activeNavigationItems, getPageMeta } from "../config/navigation";
import { useAuth } from "../context/AuthContext";
import useSocket from "../hooks/useSocket";
import "../styles/layout.css";

const titleCase = (value = "") =>
  String(value)
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());

function MainLayout({ children }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const token = localStorage.getItem("accessToken");
  const dropdownRef = useRef(null);
  const role = user?.role || "viewer";
  const pageMeta = getPageMeta(location.pathname);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);

  const availableItems = useMemo(
    () => activeNavigationItems.filter((item) => item.roles.includes(role)),
    [role]
  );

  const socketState = useSocket(token, {});

  const isActive = (path) =>
    location.pathname === path || location.pathname.startsWith(`${path}/`);

  useEffect(() => {
    setMobileSidebarOpen(false);
    setAccountOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setAccountOpen(false);
      }
    };

    document.addEventListener("mousedown", handleOutsideClick);
    return () => document.removeEventListener("mousedown", handleOutsideClick);
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const liveTone =
    socketState.connectionStatus === "connected"
      ? "healthy"
      : socketState.connectionStatus === "error"
        ? "critical"
        : "warning";

  return (
    <div className="layout layout--soc-shell">
      <aside
        className={`soc-sidebar${sidebarCollapsed ? " soc-sidebar--collapsed" : ""}${
          mobileSidebarOpen ? " soc-sidebar--mobile-open" : ""
        }`}
      >
        <div className="soc-sidebar__top">
          <Link to="/dashboard" className="soc-sidebar__brand">
            <span className="soc-sidebar__mark">TL</span>
            <div className="soc-sidebar__brand-copy">
              <strong>ThreatLens</strong>
              <span>IDS Dashboard</span>
            </div>
          </Link>

          <button
            type="button"
            className="soc-sidebar__collapse"
            onClick={() => setSidebarCollapsed((current) => !current)}
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {sidebarCollapsed ? ">" : "<"}
          </button>
        </div>

        <div className="soc-sidebar__section-label">Active Modules</div>

        <nav className="soc-sidebar__nav" aria-label="Primary navigation">
          {availableItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`soc-sidebar__link${isActive(item.path) ? " active" : ""}`}
              title={sidebarCollapsed ? item.label : undefined}
            >
              <span className="soc-sidebar__chip">{item.shortLabel}</span>
              <span className="soc-sidebar__text">{item.label}</span>
            </Link>
          ))}
        </nav>

        <div className="soc-sidebar__footer">
          <div className="soc-sidebar__footer-card">
            <span>Signed in as</span>
            <strong>{titleCase(role)}</strong>
          </div>
        </div>
      </aside>

      {mobileSidebarOpen ? (
        <button
          type="button"
          className="soc-sidebar__backdrop"
          onClick={() => setMobileSidebarOpen(false)}
          aria-label="Close sidebar"
        />
      ) : null}

      <div className={`soc-shell${sidebarCollapsed ? " soc-shell--expanded" : ""}`}>
        <header className="soc-topbar">
          <div className="soc-topbar__left">
            <button
              type="button"
              className="soc-topbar__menu"
              onClick={() => setMobileSidebarOpen((current) => !current)}
              aria-label="Toggle navigation"
            >
              Menu
            </button>
            <div className="soc-topbar__title-wrap">
              <span className="soc-topbar__eyebrow">{pageMeta.eyebrow}</span>
              <h1>{pageMeta.label}</h1>
            </div>
          </div>

          <div className="soc-topbar__right" ref={dropdownRef}>
            <div className={`soc-status-badge soc-status-badge--${liveTone}`}>
              <span className="soc-status-badge__dot" />
              <span>
                {socketState.connectionStatus === "connected"
                  ? "Live"
                  : socketState.connectionStatus === "error"
                    ? "Disconnected"
                    : "Syncing"}
              </span>
            </div>

            {user ? (
              <div className={`soc-account${accountOpen ? " open" : ""}`}>
                <button
                  type="button"
                  className="soc-account__button"
                  onClick={() => setAccountOpen((current) => !current)}
                >
                  <span className="soc-account__avatar">{String(user.email || "U").charAt(0).toUpperCase()}</span>
                  <span className="soc-account__meta">
                    <strong>{titleCase(role)}</strong>
                    <small>{user.email}</small>
                  </span>
                  <span className="soc-account__caret">+</span>
                </button>

                <div className="soc-account__menu">
                  <div className="soc-account__menu-head">
                    <strong>{user.email}</strong>
                    <span>{titleCase(role)}</span>
                  </div>
                  <button type="button" className="soc-account__menu-action" onClick={handleLogout}>
                    Logout
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </header>

        <main className="main-content main-content--soc">{children}</main>
      </div>
    </div>
  );
}

export default MainLayout;
