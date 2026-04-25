import { BrowserRouter as Router, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import ProtectedRoute from "./context/ProtectedRoute";

/* ================= PAGES ================= */

import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";

import Dashboard from "./pages/Dashboard";
import Overview from "./pages/Overview";
import Upload from "./pages/Upload";
import LiveMonitoring from "./pages/LiveMonitoring";
import Alerts from "./pages/Alerts";
import Logs from "./pages/Logs";
import Reports from "./pages/Reports";
import ModelHealth from "./pages/ModelHealth";

/* 🔥 NEW PAGES (VERY IMPORTANT) */
import Incidents from "./pages/Incidents";
import ThreatMap from "./pages/ThreatMap";
import BlockedIPs from "./pages/BlockedIPs";
import Users from "./pages/Users";
import Rules from "./pages/Rules";
import Settings from "./pages/Settings";
import Assets from "./pages/Assets";

import "./App.css";

/* ================= BACKGROUND ================= */

const pageBackgroundStyle = {
  "--app-page-background-image": `url(${process.env.PUBLIC_URL}/cropped.jpeg)`,
};

/* ================= ROLE HELPERS ================= */

const normalizeRole = (role) => {
  if (!role) return "";
  return String(role).toLowerCase().trim() === "user"
    ? "analyst"
    : String(role).toLowerCase().trim();
};

const isAllowedRole = (userRole, allowedRoles = []) => {
  const normalizedUserRole = normalizeRole(userRole);
  return allowedRoles.map(normalizeRole).includes(normalizedUserRole);
};

const getDefaultAuthenticatedRoute = (role) => {
  const normalizedRole = normalizeRole(role);

  if (["admin", "analyst", "viewer"].includes(normalizedRole)) {
    return "/dashboard";
  }

  return "/logs";
};

/* ================= SHELL ================= */

const PageShell = ({ children }) => (
  <div className="app-page-background" style={pageBackgroundStyle}>
    {children}
  </div>
);

const FullPageLoading = () => (
  <PageShell>
    <div className="app-loading-screen">Loading ThreatLens...</div>
  </PageShell>
);

/* ================= ROLE ROUTE ================= */

const RoleRoute = ({ children, allowedRoles = [] }) => {
  const { user, loading } = useAuth();

  if (loading) return <FullPageLoading />;
  if (!user) return <Navigate to="/login" replace />;

  if (!isAllowedRole(user.role, allowedRoles)) {
    return <Navigate to={getDefaultAuthenticatedRoute(user.role)} replace />;
  }

  return children;
};

const AppPage = ({
  children,
  allowedRoles = ["admin", "analyst", "user", "viewer"],
}) => (
  <PageShell>
    <ProtectedRoute>
      <RoleRoute allowedRoles={allowedRoles}>{children}</RoleRoute>
    </ProtectedRoute>
  </PageShell>
);

/* ================= HOME ================= */

const HomeRoute = () => {
  const { user, loading } = useAuth();

  if (loading) return <FullPageLoading />;

  if (!user) return <Landing />;

  return <Navigate to={getDefaultAuthenticatedRoute(user.role)} replace />;
};

const GuestRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) return <FullPageLoading />;
  if (user) return <Navigate to="/dashboard" replace />;

  return <PageShell>{children}</PageShell>;
};

/* ================= ROUTES ================= */

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<HomeRoute />} />

      <Route path="/login" element={<GuestRoute><Login /></GuestRoute>} />
      <Route path="/register" element={<GuestRoute><Register /></GuestRoute>} />

      {/* CORE */}
      <Route path="/dashboard" element={<AppPage><Dashboard /></AppPage>} />
      <Route path="/overview" element={<AppPage><Overview /></AppPage>} />
      <Route path="/live-monitoring" element={<AppPage><LiveMonitoring /></AppPage>} />

      {/* DATA */}
      <Route path="/upload" element={<AppPage allowedRoles={["admin","analyst"]}><Upload /></AppPage>} />
      <Route path="/alerts" element={<AppPage><Alerts /></AppPage>} />
      <Route path="/logs" element={<AppPage><Logs /></AppPage>} />

      {/* SECURITY */}
      <Route path="/incidents" element={<AppPage allowedRoles={["admin","analyst"]}><Incidents /></AppPage>} />
      <Route path="/threat-map" element={<AppPage><ThreatMap /></AppPage>} />
      <Route path="/blocked-ips" element={<AppPage allowedRoles={["admin","analyst"]}><BlockedIPs /></AppPage>} />

      {/* ML */}
      <Route path="/reports" element={<AppPage allowedRoles={["admin","analyst"]}><Reports /></AppPage>} />
      <Route path="/model-health" element={<AppPage allowedRoles={["admin","analyst"]}><ModelHealth /></AppPage>} />

      {/* MANAGEMENT */}
      <Route path="/users" element={<AppPage allowedRoles={["admin"]}><Users /></AppPage>} />
      <Route path="/rules" element={<AppPage allowedRoles={["admin","analyst"]}><Rules /></AppPage>} />
      <Route path="/settings" element={<AppPage allowedRoles={["admin"]}><Settings /></AppPage>} />
      <Route path="/assets" element={<AppPage allowedRoles={["admin","analyst"]}><Assets /></AppPage>} />

      {/* FALLBACK */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

/* ================= APP ================= */

function App() {
  return (
    <Router>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </Router>
  );
}

export default App;