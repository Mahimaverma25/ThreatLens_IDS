import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import '../styles/Landing.css';

const Landing = () => {
  const { user } = useAuth();

  return (
    <div className="landing-container">
      <div 
        className="landing-background"
        style={{
          backgroundImage: `url(${process.env.PUBLIC_URL}/cropped.jpeg)`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundAttachment: 'fixed',
        }}
      >
        {/* Overlay for better text readability */}
        <div className="landing-overlay"></div>

        {/* Content */}
        <div className="landing-content">
          <div className="landing-header">
            <h1 className="landing-title">ThreatLens</h1>
            <p className="landing-subtitle">
              Advanced Security Threat Detection & Response Platform
            </p>
          </div>

          <div className="landing-description">
            <p>
              Monitor, detect, and respond to security threats in real-time with 
              our intelligent threat detection engine and comprehensive analytics dashboard.
            </p>
          </div>

          <div className="landing-about">
            <h2>What is ThreatLens?</h2>
            <p>
              ThreatLens is a cybersecurity monitoring platform that centralizes traffic logs,
              flags suspicious behavior, and helps security teams investigate incidents faster.
              It combines log ingestion, anomaly signals, rule-based detection, and live dashboards
              so organizations can move from raw events to clear threat visibility.
            </p>
          </div>

          <div className="landing-cta">
            {user ? (
              <Link to="/dashboard" className="cta-button primary">
                Go to Dashboard
              </Link>
            ) : (
              <>
                <Link to="/login" className="cta-button primary">
                  Sign In
                </Link>
                <Link to="/register" className="cta-button secondary">
                  Get Started
                </Link>
              </>
            )}
          </div>

          {/* Feature Highlights */}
          <div className="landing-features">
            <div className="feature-card">
              <div className="feature-icon">🛡️</div>
              <h3>Real-Time Detection</h3>
              <p>Detect threats as they happen with advanced anomaly detection</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">📊</div>
              <h3>Advanced Analytics</h3>
              <p>Comprehensive dashboards and detailed threat analysis</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">⚡</div>
              <h3>Fast Response</h3>
              <p>Respond to threats quickly with actionable intelligence</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🔐</div>
              <h3>Enterprise Security</h3>
              <p>Enterprise-grade security for your organization</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🧠</div>
              <h3>Hybrid Intelligence</h3>
              <p>Combine rule-based checks with anomaly insights from your IDS pipeline</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">📥</div>
              <h3>Flexible Ingestion</h3>
              <p>Collect logs from agents, uploads, and simulated traffic in one place</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">👥</div>
              <h3>Role-Based Access</h3>
                <p>Separate admin and viewer access with protected routes and server-side RBAC</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">📣</div>
              <h3>Live Alert Workflow</h3>
              <p>Receive socket-driven updates and track alert activity as incidents evolve</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Landing;
