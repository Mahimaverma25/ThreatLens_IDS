import React, { useEffect, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { auth as authApi } from "../services/api";
import "../styles/auth.css";

const VerifyEmail = () => {
  const [searchParams] = useSearchParams();
  const location = useLocation();
  const initialStatus = location.state?.status || (searchParams.get("token") ? "loading" : "info");
  const initialMessage = location.state?.message || (
    searchParams.get("token")
      ? "Verifying your email now..."
      : "Check your inbox for the verification email. If it has not arrived yet, you can request a new one below."
  );
  const [status, setStatus] = useState(initialStatus);
  const [message, setMessage] = useState(initialMessage);
  const [email, setEmail] = useState(() => searchParams.get("email") || "");
  const [previewUrl, setPreviewUrl] = useState(() => location.state?.previewUrl || "");
  const [submitting, setSubmitting] = useState(false);
  const token = searchParams.get("token") || "";

  useEffect(() => {
    const verify = async () => {
      if (!token) {
        return;
      }

      if (!email) {
        setStatus("error");
        setMessage("The verification link is incomplete. Request a new verification email.");
        return;
      }

      try {
        const response = await authApi.verifyEmail(email, token);
        setStatus("success");
        setMessage(response.data?.message || "Email verified successfully. You can sign in now.");
        setPreviewUrl("");
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
    setSubmitting(true);
    try {
      const response = await authApi.resendVerification(email);
      setStatus("info");
      setMessage(response.data?.message || "Verification email sent successfully.");
      setPreviewUrl(response.data?.previewUrl || "");
    } catch (error) {
      setStatus("error");
      setMessage(
        error?.response?.data?.message ||
        "Failed to resend verification email."
      );
      setPreviewUrl("");
    } finally {
      setSubmitting(false);
    }
  };

  const statusClassName =
    status === "success"
      ? "success-message"
      : status === "error"
        ? "error-message"
        : "info-message";

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-badge">ThreatLens Email Security</div>
        <h1>ThreatLens</h1>
        <h2>Verify Email</h2>
        <p className="auth-description">
          Finish setting up your account by confirming the email address you used during registration.
        </p>

        <div className={statusClassName}>{message}</div>

        {previewUrl && (
          <div className="info-message">
            Development preview link: <a href={previewUrl}>Open verification link</a>
          </div>
        )}

        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@organization.com"
          />
        </div>

        <button type="button" className="auth-secondary-button" onClick={handleResend} disabled={!email || submitting}>
          {submitting ? "Sending..." : "Resend Verification Email"}
        </button>

        <p className="auth-link">
          Ready to continue? <Link to="/login">Go to sign in</Link>
        </p>
      </div>
    </div>
  );
};

export default VerifyEmail;
