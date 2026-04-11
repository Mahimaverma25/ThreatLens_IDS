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
    <RoleRoute allowedRoles={["admin"]}>
      <Dashboard />
    </RoleRoute>
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
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* ================= ALERTS ================= */}
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <RoleRoute allowedRoles={["admin", "analyst"]}>
                  <Alerts />
                </RoleRoute>
              </ProtectedRoute>
            }
          />

          <Route
            path="/alerts/:id"
            element={
              <ProtectedRoute>
                <RoleRoute allowedRoles={["admin", "analyst"]}>
                  <AlertDetails />
                </RoleRoute>
              </ProtectedRoute>
            }
          />

          {/* ================= LOGS ================= */}
          <Route
            path="/logs"
            element={
              <ProtectedRoute>
                <RoleRoute allowedRoles={["admin", "analyst", "user"]}>
                  <Logs />
                </RoleRoute>
              </ProtectedRoute>
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