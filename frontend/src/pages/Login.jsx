import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getActiveApiBaseUrl } from "../services/connection";
import "../styles/auth.css";

const API_TARGET = getActiveApiBaseUrl();

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const formatLoginError = (err) => {
    if (err?.response?.data?.message) {
      return err.response.data.message;
    }

    if (err?.message === "Network Error") {
      return `Unable to reach the ThreatLens API at ${API_TARGET}. Make sure the local backend is running and reachable.`;
    }

    return err?.message || "Login failed. Please try again.";
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await login(email, password, role);
      const user = res?.user;

      if (!user) {
        throw new Error("Invalid server response");
      }

      navigate("/dashboard");
    } catch (err) {
      console.error("Login error:", err);
      setError(formatLoginError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-badge">ThreatLens Security Console</div>
        <h1>ThreatLens</h1>
        <h2>Secure Sign In</h2>
        <p className="auth-description">
          Access your monitoring workspace, review live telemetry, and respond to active threats.
        </p>

        <div className="info-message">
          Choose the portal role before signing in. Viewer is open for normal access, while Analyst and Admin must match the role assigned to the account.
        </div>

        {error && <div className="error-message">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
              autoComplete="email"
              placeholder="viewer@threatlens.com"
            />
          </div>

          <div className="form-group">
            <label>Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              disabled={loading}
            >
              <option value="viewer">Viewer</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
              autoComplete="current-password"
              placeholder="Enter your password"
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Enter Dashboard"}
          </button>
        </form>

        <p className="auth-link">
          Don&apos;t have an account? <Link to="/register">Create one now</Link>
        </p>
      </div>
    </div>
  );
};

export default Login;
