import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getPageMeta, navigationSections } from "../config/navigation";

const PRIMARY_PATHS = [
  "/dashboard",
  "/overview",
  "/upload",
  "/reports",
  "/live-monitoring",
  "/access",
  "/blocked-ips",
];

const AppNavbar = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const menuRef = useRef(null);
  const [isAdminMenuOpen, setIsAdminMenuOpen] = useState(false);
  const pageMeta = getPageMeta(location.pathname);
  const role = user?.role || "viewer";

  const allItems = useMemo(
    () =>
      navigationSections
        .flatMap((section) => section.items)
        .filter((item) => item.roles.includes(role)),
    [role]
  );

  const itemByPath = useMemo(
    () =>
      allItems.reduce((lookup, item) => {
        lookup[item.path] = item;
        return lookup;
      }, {}),
    [allItems]
  );

  const primaryItems = PRIMARY_PATHS.map((path) => itemByPath[path]).filter(Boolean);
  const adminItems = allItems.filter((item) => !PRIMARY_PATHS.includes(item.path));

  const isActive = (path) =>
    location.pathname === path || location.pathname.startsWith(`${path}/`);

  const isAdminActive = adminItems.some((item) => isActive(item.path));

  useEffect(() => {
    setIsAdminMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsAdminMenuOpen(false);
      }
    };

    document.addEventListener("mousedown", handleOutsideClick);
    return () => document.removeEventListener("mousedown", handleOutsideClick);
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <header className="navbar navbar--commandbar" ref={menuRef}>
      <div className="commandbar">
        <div className="commandbar-brand">
          <Link to="/dashboard" className="commandbar-brand__link">
            <span className="brand-mark">TL</span>
            <span className="commandbar-brand__copy">
              <span className="commandbar-brand__eyebrow">{pageMeta.eyebrow}</span>
              <strong>ThreatLens IDS Dashboard</strong>
            </span>
          </Link>
        </div>

        <nav className="commandbar-nav" aria-label="ThreatLens Navigation">
          {primaryItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`commandbar-link${isActive(item.path) ? " active" : ""}`}
            >
              <span className="commandbar-link__dot" />
              <span>{item.label}</span>
            </Link>
          ))}

          {adminItems.length > 0 && (
            <div className={`commandbar-dropdown${isAdminMenuOpen ? " open" : ""}`}>
              <button
                type="button"
                className={`commandbar-link commandbar-link--button${isAdminActive ? " active" : ""}`}
                onClick={() => setIsAdminMenuOpen((current) => !current)}
              >
                <span className="commandbar-link__dot" />
                <span>Admin</span>
                <span className="commandbar-link__caret">v</span>
              </button>

              <div className="commandbar-menu commandbar-menu--admin">
                {adminItems.map((item) => (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`commandbar-menu__item${isActive(item.path) ? " active" : ""}`}
                  >
                    <span className="nav-chip">{item.shortLabel}</span>
                    <span className="commandbar-menu__label">{item.label}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </nav>

        <div className="commandbar-tools">
          <div className="commandbar-workspace">
            <span className="panel-label">Workspace</span>
            <strong>{pageMeta.label}</strong>
          </div>

          {user && (
            <button type="button" className="commandbar-account" onClick={handleLogout}>
              <span className="commandbar-account__status" />
              <span>{user.role}</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};

export default AppNavbar;
