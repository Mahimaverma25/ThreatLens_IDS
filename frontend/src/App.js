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

import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Logs from "./pages/Logs";
import AlertDetails from "./pages/AlertDetails";

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

  return (
    <div className="app-page-background" style={pageBackgroundStyle}>
      <RoleRoute allowedRoles={["admin"]}>
        <Dashboard />
      </RoleRoute>
    </div>
  );
};

function App() {
  return (
    <Router>
      <AuthProvider>
        <Routes>

          {/* ================= HOME ================= */}
          <Route path="/" element={<HomeRoute />} />

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

          {/* ================= ALERTS ================= */}
          <Route
            path="/alerts"
            element={
              <div className="app-page-background" style={pageBackgroundStyle}>
                <ProtectedRoute>
                  <RoleRoute allowedRoles={["admin", "analyst"]}>
                    <Alerts />
                  </RoleRoute>
                </ProtectedRoute>
              </div>
            }
          />

          <Route
            path="/alerts/:id"
            element={
              <div className="app-page-background" style={pageBackgroundStyle}>
                <ProtectedRoute>
                  <RoleRoute allowedRoles={["admin", "analyst"]}>
                    <AlertDetails />
                  </RoleRoute>
                </ProtectedRoute>
              </div>
            }
          />

          {/* ================= LOGS ================= */}
          <Route
            path="/logs"
            element={
              <div className="app-page-background" style={pageBackgroundStyle}>
                <ProtectedRoute>
                  <RoleRoute allowedRoles={["admin", "analyst", "user"]}>
                    <Logs />
                  </RoleRoute>
                </ProtectedRoute>
              </div>
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