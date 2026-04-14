import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "../styles/auth.css";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [previewUrl, setPreviewUrl] = useState("");
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setInfo("");
    setPreviewUrl("");
    setLoading(true);

    try {
      const res = await login(email, password);
      const user = res?.user;

      if (!user) {
        throw new Error("Invalid server response");
      }

      if (user.role === "admin") {
        navigate("/");
      } else {
        navigate("/logs");
      }
    } catch (err) {
      console.error("Login error:", err);
      if (err?.response?.data?.verificationRequired) {
        setInfo(
          err?.response?.data?.message ||
          "Email verification required. Check your inbox before signing in."
        );
        setPreviewUrl(err?.response?.data?.previewUrl || "");
      } else {
        setError(
          err?.response?.data?.message ||
          err?.message ||
          "Login failed. Please try again."
        );
      }
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

        {error && <div className="error-message">{error}</div>}
        {info && <div className="info-message">{info}</div>}
        {previewUrl && (
          <div className="info-message">
            Development preview link: <a href={previewUrl}>Open verification link</a>
          </div>
        )}

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
        <p className="auth-link">
          Need to verify? <Link to="/verify-email">Open verification page</Link>
        </p>
      </div>
    </div>
  );
};

export default Login;
