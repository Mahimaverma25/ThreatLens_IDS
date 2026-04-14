import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

import { AuthProvider } from "./context/AuthContext";
import { useAuth } from "./context/AuthContext";
import ProtectedRoute from "./context/ProtectedRoute";

import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";

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

/* ================= ROLE-BASED WRAPPER ================= */

const RoleRoute = ({ children, allowedRoles }) => {
  const { user } = useAuth();

  if (!user) return <Navigate to="/login" />;

  if (!allowedRoles.includes(user.role)) {
    return <Navigate to="/logs" />;
  }

  return children;
};

/* ================= HOME ROUTE (LANDING OR DASHBOARD) ================= */

const HomeRoute = () => {
  const { user } = useAuth();

  if (!user) {
    return <Landing />;
  }

  return <Navigate to="/dashboard" replace />;
};

const AppPage = ({ children, allowedRoles = ["admin", "viewer"] }) => (
  <div className="app-page-background" style={pageBackgroundStyle}>
    <ProtectedRoute>
      <RoleRoute allowedRoles={allowedRoles}>
        {children}
      </RoleRoute>
    </ProtectedRoute>
  </div>
);

function App() {
  return (
    <Router>
      <AuthProvider>
        <Routes>

          {/* ================= HOME ================= */}
          <Route path="/" element={<HomeRoute />} />

          <Route
            path="/dashboard"
            element={
              <AppPage>
                <Dashboard />
              </AppPage>
            }
          />

          {/* ================= PUBLIC ROUTES ================= */}
          <Route
            path="/login"
            element={
              <div className="app-page-background" style={pageBackgroundStyle}>
                <Login />
              </div>
            }
          />
          <Route
            path="/register"
            element={
              <div className="app-page-background" style={pageBackgroundStyle}>
                <Register />
              </div>
            }
          />
          <Route
            path="/verify-email"
            element={
              <div className="app-page-background" style={pageBackgroundStyle}>
                <VerifyEmail />
              </div>
            }
          />

          {/* ================= ALERTS ================= */}
          <Route
            path="/alerts"
            element={
              <AppPage allowedRoles={["admin", "viewer"]}>
                <Alerts />
              </AppPage>
            }
          />

          <Route
            path="/alerts/:id"
            element={
              <AppPage allowedRoles={["admin", "viewer"]}>
                <AlertDetails />
              </AppPage>
            }
          />

          <Route
            path="/logs"
            element={
              <AppPage>
                <Logs />
              </AppPage>
            }
          />

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
            path="/reports"
            element={
              <AppPage allowedRoles={["admin", "viewer"]}>
                <Reports />
              </AppPage>
            }
          />

          <Route
            path="/threat-map"
            element={
              <AppPage allowedRoles={["admin", "viewer"]}>
                <ThreatMap />
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
          <Route path="*" element={<Navigate to="/" />} />

        </Routes>
      </AuthProvider>
    </Router>
  );
}

export default App;
