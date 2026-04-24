import { BrowserRouter as Router, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import ProtectedRoute from "./context/ProtectedRoute";
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
import "./App.css";

const pageBackgroundStyle = {
  "--app-page-background-image": `url(${process.env.PUBLIC_URL}/cropped.jpeg)`,
};

const normalizeRole = (role) => {
  if (!role) return "";
  return String(role).toLowerCase().trim() === "user" ? "analyst" : String(role).toLowerCase().trim();
};

const isAllowedRole = (userRole, allowedRoles = []) => {
  const normalizedUserRole = normalizeRole(userRole);
  return allowedRoles.map(normalizeRole).includes(normalizedUserRole);
};

const getDefaultAuthenticatedRoute = (role) => {
  const normalizedRole = normalizeRole(role);

  if (normalizedRole === "analyst" || normalizedRole === "admin" || normalizedRole === "viewer") {
    return "/dashboard";
  }

  return "/logs";
};

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

const RoleRoute = ({ children, allowedRoles = [] }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <FullPageLoading />;
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

const HomeRoute = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return <FullPageLoading />;
  }

  if (!user) {
    return <Landing />;
  }

  return <Navigate to={getDefaultAuthenticatedRoute(user.role)} replace />;
};

const GuestRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <FullPageLoading />;
  }

  if (user) {
    return <Navigate to={getDefaultAuthenticatedRoute(user.role)} replace />;
  }

  return <PageShell>{children}</PageShell>;
};

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<HomeRoute />} />

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

      <Route
        path="/dashboard"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <Dashboard />
          </AppPage>
        }
      />

      <Route
        path="/overview"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <Overview />
          </AppPage>
        }
      />

      <Route
        path="/upload"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <Upload />
          </AppPage>
        }
      />

      <Route
        path="/live-monitoring"
        element={
          <AppPage allowedRoles={["admin", "analyst", "viewer"]}>
            <LiveMonitoring />
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
        path="/model-health"
        element={
          <AppPage allowedRoles={["admin", "analyst"]}>
            <ModelHealth />
          </AppPage>
        }
      />

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
