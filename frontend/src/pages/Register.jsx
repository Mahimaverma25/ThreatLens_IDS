import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "../styles/auth.css";

const Register = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [previewUrl, setPreviewUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setPreviewUrl("");
    setLoading(true);

    try {
      const response = await register(email, password, username);
      setSuccess(
        response?.message ||
        "Registration successful. Check your email to verify your account."
      );
      setPreviewUrl(response?.previewUrl || "");
      setPassword("");
    } catch (err) {
      setError(err.response?.data?.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-badge">ThreatLens Access Setup</div>
        <h1>ThreatLens</h1>
        <h2>Create Account</h2>
        <p className="auth-description">
            Create a viewer account to monitor dashboards, alerts, logs, and reports with read-only access.
        </p>

        {error && <div className="error-message">{error}</div>}
        {success && <div className="success-message">{success}</div>}
        {previewUrl && (
          <div className="info-message">
            Development preview link: <a href={previewUrl}>Open verification link</a>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={loading}
              placeholder="Choose a username"
            />
          </div>

          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
              placeholder="you@organization.com"
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
              placeholder="Create a strong password"
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? "Creating account..." : "Register Securely"}
          </button>
        </form>

        <p className="auth-link">
          Already have an account? <Link to="/login">Sign in here</Link>
        </p>
        <p className="auth-link">
          Already registered but not verified? <Link to="/verify-email">Verify email</Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
