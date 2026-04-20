import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";

import { AuthProvider, useAuth } from "./context/AuthContext";
import ProtectedRoute from "./context/ProtectedRoute";

import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";

import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Logs from "./pages/Logs";
import AlertDetails from "./pages/AlertDetails";
import Incidents from "./pages/Incidents";
import Assets from "./pages/Assets";
import Rules from "./pages/Rules";
import ThreatIntel from "./pages/ThreatIntel";
import Reports from "./pages/Reports";
import AccessManagement from "./pages/AccessManagement";
import ModelHealth from "./pages/ModelHealth";
import ResponsePlaybooks from "./pages/ResponsePlaybooks";
import ThreatMap from "./pages/ThreatMap";

import "./App.css";

const pageBackgroundStyle = {
  "--app-page-background-image": `url(${process.env.PUBLIC_URL}/cropped.jpeg)`,
};

/* ================= ROLE HELPERS ================= */

const normalizeRole = (role) => {
  if (!role) return "";

  const value = String(role).toLowerCase().trim();

  // Backward compatibility for older backend/frontend role names
  if (value === "viewer") return "analyst";
  return value;
};

const isAllowedRole = (userRole, allowedRoles = []) => {
  const normalizedUserRole = normalizeRole(userRole);
  const normalizedAllowedRoles = allowedRoles.map(normalizeRole);

  return normalizedAllowedRoles.includes(normalizedUserRole);
};

const getDefaultAuthenticatedRoute = (role) => {
  const normalizedRole = normalizeRole(role);

  if (normalizedRole === "admin") return "/dashboard";
  if (normalizedRole === "analyst") return "/dashboard";
  if (normalizedRole === "user") return "/logs";

  return "/dashboard";
};

/* ================= COMMON PAGE WRAPPER ================= */

const PageShell = ({ children }) => (
  <div className="app-page-background" style={pageBackgroundStyle}>
    {children}
  </div>
);

/* ================= ROUTE GUARDS ================= */

const RoleRoute = ({ children, allowedRoles = [] }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <PageShell>
        <div className="flex min-h-screen items-center justify-center text-white text-lg font-medium">
          Loading...
        </div>
      </PageShell>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (!isAllowedRole(user.role, allowedRoles)) {
    return <Navigate to={getDefaultAuthenticatedRoute(user.role)} replace />;
  }

  return children;
};

const AppPage = ({ children, allowedRoles = ["admin", "analyst", "user", "viewer"] }) => (
  <PageShell>
    <ProtectedRoute>
      <RoleRoute allowedRoles={allowedRoles}>{children}</RoleRoute>
    </ProtectedRoute>
  </PageShell>
);

/* ================= PUBLIC/AUTH ROUTES ================= */

const HomeRoute = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <PageShell>
        <div className="flex min-h-screen items-center justify-center text-white text-lg font-medium">
          Loading...
        </div>
      </PageShell>
    );
  }

  if (!user) {
    return <Landing />;
  }

  return <Navigate to={getDefaultAuthenticatedRoute(user.role)} replace />;
};

const GuestRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <PageShell>
        <div className="flex min-h-screen items-center justify-center text-white text-lg font-medium">
          Loading...
        </div>
      </PageShell>
    );
  }

  if (user) {
    return <Navigate to={getDefaultAuthenticatedRoute(user.role)} replace />;
  }

  return <PageShell>{children}</PageShell>;
};

/* ================= APP ================= */

function AppRoutes() {
  return (
    <Routes>
      {/* ================= HOME ================= */}
      <Route path="/" element={<HomeRoute />} />

      {/* ================= PUBLIC ROUTES ================= */}
      <Route
        path="/login"
        element={
          <GuestRoute>
            <Login />
          </GuestRoute>
        }
      />

      <Route
        path="/register"
        element={
          <GuestRoute>
            <Register />
          </GuestRoute>
        }
      />

      {/* ================= SHARED PROTECTED ROUTES ================= */}
      <Route
        path="/dashboard"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <Dashboard />
          </AppPage>
        }
      />

      <Route
        path="/alerts"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <Alerts />
          </AppPage>
        }
      />

      <Route
        path="/alerts/:id"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <AlertDetails />
          </AppPage>
        }
      />

      <Route
        path="/logs"
        element={
          <AppPage allowedRoles={["admin", "analyst", "user", "viewer"]}>
            <Logs />
          </AppPage>
        }
      />

      <Route
        path="/reports"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <Reports />
          </AppPage>
        }
      />

      <Route
        path="/threat-map"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <ThreatMap />
          </AppPage>
        }
      />

      {/* ================= ADMIN ROUTES ================= */}
      <Route
        path="/incidents"
        element={
          <AppPage allowedRoles={["admin"]}>
            <Incidents />
          </AppPage>
        }
      />

      <Route
        path="/assets"
        element={
          <AppPage allowedRoles={["admin"]}>
            <Assets />
          </AppPage>
        }
      />

      <Route
        path="/rules"
        element={
          <AppPage allowedRoles={["admin"]}>
            <Rules />
          </AppPage>
        }
      />

      <Route
        path="/threat-intel"
        element={
          <AppPage allowedRoles={["admin"]}>
            <ThreatIntel />
          </AppPage>
        }
      />

      <Route
        path="/access"
        element={
          <AppPage allowedRoles={["admin"]}>
            <AccessManagement />
          </AppPage>
        }
      />

      <Route
        path="/model-health"
        element={
          <AppPage allowedRoles={["admin"]}>
            <ModelHealth />
          </AppPage>
        }
      />

      <Route
        path="/playbooks"
        element={
          <AppPage allowedRoles={["admin"]}>
            <ResponsePlaybooks />
          </AppPage>
        }
      />

      {/* ================= FALLBACK ================= */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

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