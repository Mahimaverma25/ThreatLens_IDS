import React, { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { auth as authApi } from "../services/api";
import "../styles/auth.css";

const VerifyEmail = () => {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState("loading");
  const [message, setMessage] = useState("Verifying your email now...");
  const [email, setEmail] = useState(() => searchParams.get("email") || "");
  const token = searchParams.get("token") || "";

  useEffect(() => {
    const verify = async () => {
      if (!email || !token) {
        setStatus("error");
        setMessage("The verification link is incomplete. Request a new verification email.");
        return;
      }

      try {
        const response = await authApi.verifyEmail(email, token);
        setStatus("success");
        setMessage(response.data?.message || "Email verified successfully. You can sign in now.");
      } catch (error) {
        setStatus("error");
        setMessage(
          error?.response?.data?.message ||
          "Verification failed. Request a new verification email and try again."
        );
      }
    };

    verify();
  }, [email, token]);

  const handleResend = async () => {
    try {
      const response = await authApi.resendVerification(email);
      setStatus("info");
      setMessage(response.data?.message || "Verification email sent successfully.");
    } catch (error) {
      setStatus("error");
      setMessage(
        error?.response?.data?.message ||
        "Failed to resend verification email."
      );
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-badge">ThreatLens Email Security</div>
        <h1>ThreatLens</h1>
        <h2>Verify Email</h2>
        <p className="auth-description">
          Confirm your email address before signing in to the ThreatLens security workspace.
        </p>

        <div
          className={`${
            status === "success"
              ? "success-message"
              : status === "info"
                ? "info-message"
                : "error-message"
          }`}
        >
          {message}
        </div>

        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@organization.com"
          />
        </div>

        <button type="button" onClick={handleResend}>
          Resend Verification Email
        </button>

        <p className="auth-link">
          Ready to continue? <Link to="/login">Go to sign in</Link>
        </p>
      </div>
    </div>
  );
};

export default VerifyEmail;
