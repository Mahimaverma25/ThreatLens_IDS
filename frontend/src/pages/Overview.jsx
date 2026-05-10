import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";

const modelCards = [
  {
    name: "Random Forest",
    badge: "Primary Classifier",
    score: "Evaluation Ready",
    color: "green",
    description:
      "Used for supervised attack classification when trained IDS datasets and saved model files are connected to the ML service.",
    metrics: {
      Status: "Configured",
      Role: "Classification",
      Output: "Attack Label",
      Explainability: "Medium",
    },
    note: "Recommended main ML model for ThreatLens",
  },
  {
    name: "SVM Classifier",
    badge: "Anomaly Boundary",
    score: "Optional ML",
    color: "blue",
    description:
      "Supports suspicious traffic separation by identifying boundaries between normal and abnormal behavior patterns.",
    metrics: {
      Status: "Supported",
      Role: "Anomaly Support",
      Output: "Normal / Suspicious",
      Explainability: "Medium",
    },
    note: "Useful for academic ML comparison",
  },
  {
    name: "Rule-Based Engine",
    badge: "Real-Time Logic",
    score: "Active",
    color: "orange",
    description:
      "Detects known attacks such as brute force, port scan, DDoS-like bursts, suspicious IP activity, and abnormal telemetry patterns.",
    metrics: {
      Status: "Active",
      Role: "Known Attack Detection",
      Output: "Alert",
      Explainability: "High",
    },
    note: "Most reliable for real-time local testing",
  },
];

const attackCategories = [
  {
    name: "Port Scanning",
    status: "Implemented",
    detail: "Detects repeated access to multiple ports",
    icon: "🔍",
    color: "blue",
  },
  {
    name: "Brute Force",
    status: "Implemented",
    detail: "Detects repeated failed authentication attempts",
    icon: "🔑",
    color: "cyan",
  },
  {
    name: "DDoS Pattern",
    status: "Rule-Based",
    detail: "Detects abnormal request or packet burst behavior",
    icon: "🛡️",
    color: "yellow",
  },
  {
    name: "Suspicious IP",
    status: "Implemented",
    detail: "Tracks risky source IP behavior and watchlist entries",
    icon: "🌐",
    color: "red",
  },
  {
    name: "Log Anomaly",
    status: "Supported",
    detail: "Analyzes abnormal log activity from agents",
    icon: "📄",
    color: "green",
  },
  {
    name: "Incident Workflow",
    status: "Implemented",
    detail: "Converts high-risk alerts into investigation cases",
    icon: "🚨",
    color: "gray",
  },
];

const stats = [
  { value: "Hybrid", label: "Detection Type" },
  { value: "NIDS + HIDS", label: "Monitoring Scope" },
  { value: "Rule + ML", label: "Detection Method" },
  { value: "Real-Time", label: "Dashboard Updates" },
];

const projectModules = [
  "React.js SOC dashboard",
  "Node.js + Express backend API",
  "MongoDB event and alert storage",
  "Socket.IO live dashboard updates",
  "Snort/NIDS log collection support",
  "HIDS agent telemetry ingestion",
];

const techStack = [
  "React.js",
  "Node.js",
  "Express.js",
  "MongoDB",
  "Socket.IO",
  "Python Flask ML Service",
  "Scikit-learn",
  "Snort Integration",
];

const features = [
  "Real-time dashboard monitoring",
  "Live alerts and logs",
  "Role-based access control",
  "Incident management workflow",
  "Threat intelligence watchlist",
  "Response playbook execution",
];

const Overview = () => {
  return (
    <MainLayout>
      <div className="tl-overview-page">
        <section className="tl-overview-hero">
          <div className="tl-hero-shield">🛡️</div>

          <h1>ThreatLens IDS</h1>
          <h3>Hybrid Intrusion Detection & Real-Time Security Monitoring</h3>

          <p>
            ThreatLens is a web-based hybrid intrusion detection platform that combines
            HIDS telemetry, NIDS/Snort log collection, rule-based detection, machine
            learning support, live alerts, incidents, and SOC-style monitoring.
          </p>

          <div className="tl-hero-actions">
            <Link to="/dashboard" className="tl-primary-btn">
              Go to Dashboard
            </Link>

            <Link to="/live-monitoring" className="tl-secondary-btn">
              Start Live Monitoring
            </Link>
          </div>
        </section>

        <section className="tl-section-heading">
          <h2>Project Overview</h2>
          <p>
            This page shows the actual ThreatLens architecture and implemented
            capabilities. Live operational data is shown on Dashboard, Logs, Alerts,
            Threat Intel, and Live Monitoring pages.
          </p>
          <span>Hybrid Pipeline: HIDS Agent + NIDS Collector + Rule Engine + ML Service</span>
        </section>

        <section className="tl-stats-grid">
          {stats.map((item) => (
            <div key={item.label} className="tl-stat-card">
              <strong>{item.value}</strong>
              <span>{item.label}</span>
            </div>
          ))}
        </section>

        <section className="tl-model-grid">
          {modelCards.map((model) => (
            <article key={model.name} className={`tl-model-card tl-${model.color}`}>
              <div className="tl-score-circle">{model.score}</div>
              <h3>{model.name}</h3>
              <span className="tl-model-badge">{model.badge}</span>
              <p>{model.description}</p>

              <div className="tl-model-metrics">
                {Object.entries(model.metrics).map(([key, value]) => (
                  <div key={key}>
                    <strong>{key}</strong>
                    <span>{value}</span>
                  </div>
                ))}
              </div>

              <small>{model.note}</small>
            </article>
          ))}
        </section>

        <section className="tl-attack-panel">
          <div className="tl-panel-title">
            <h2>Detection Coverage</h2>
            <p>
              These are the attack and monitoring categories supported by the
              ThreatLens workflow.
            </p>
          </div>

          <div className="tl-attack-grid">
            {attackCategories.map((attack) => (
              <div
                key={attack.name}
                className={`tl-attack-card tl-border-${attack.color}`}
              >
                <div className="tl-attack-icon">{attack.icon}</div>
                <h3>{attack.name}</h3>
                <strong>{attack.status}</strong>
                <span>{attack.detail}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="tl-info-grid">
          <div className="tl-info-card tl-dataset-card">
            <h2>Implemented Project Modules</h2>
            <p>
              ThreatLens is not just a static dashboard. It includes multiple modules
              for security monitoring, alerting, investigation, and response.
            </p>

            <ul>
              {projectModules.map((point) => (
                <li key={point}>{point}</li>
              ))}
            </ul>
          </div>

          <div className="tl-info-card tl-tech-card">
            <h2>Technology Stack</h2>
            <p>
              The system uses a full-stack architecture with a React frontend,
              Node.js backend, MongoDB database, and Python-based ML service.
            </p>

            <ul>
              {techStack.map((tech) => (
                <li key={tech}>{tech}</li>
              ))}
            </ul>
          </div>
        </section>

        <section className="tl-section-heading">
          <h2>Key Features and Capabilities</h2>
          <p>
            ThreatLens combines IDS monitoring, alert investigation, role-based
            access, and response workflow in one platform.
          </p>
        </section>

        <section className="tl-feature-grid">
          {features.map((feature) => (
            <div key={feature} className="tl-feature-card">
              <span>✓</span>
              <strong>{feature}</strong>
            </div>
          ))}
        </section>
      </div>
    </MainLayout>
  );
};

export default Overview;