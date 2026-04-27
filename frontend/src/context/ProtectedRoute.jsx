import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";

/* ================= ROLE NORMALIZER ================= */

const normalizeRole = (role) => {
  if (!role) return "";

  const value = String(role).toLowerCase().trim();

  if (value === "user") return "viewer";

  return value;
};

/* ================= DEFAULT REDIRECT ================= */

const getDefaultRoute = (role) => {
  const r = normalizeRole(role);

  if (r === "admin") return "/dashboard";
  if (r === "analyst") return "/dashboard";
  if (r === "viewer") return "/dashboard";

  return "/dashboard";
};

/* ================= PROTECTED ROUTE ================= */

const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, loading } = useAuth();
  const location = useLocation();

  /* ---------- LOADING STATE ---------- */
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-black text-white text-lg">
        🔐 Checking authentication...
      </div>
    );
  }

  /* ---------- NOT LOGGED IN ---------- */
  if (!user) {
    return (
      <Navigate
        to="/login"
        state={{ from: location }}
        replace
      />
    );
  }

  /* ---------- ROLE CHECK (OPTIONAL) ---------- */
  if (allowedRoles && allowedRoles.length > 0) {
    const userRole = normalizeRole(user.role);
    const allowed = allowedRoles.map(normalizeRole);

    if (!allowed.includes(userRole)) {
      return <Navigate to={getDefaultRoute(userRole)} replace />;
    }
  }

  /* ---------- ALLOWED ---------- */
  return children;
};

export default ProtectedRoute;
