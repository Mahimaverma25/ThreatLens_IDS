import { Link } from "react-router-dom";
import MainLayout from "../layout/MainLayout";

const modelCards = [
  {
    name: "Random Forest",
    badge: "Best Performer",
    score: "98.12%",
    color: "green",
    description:
      "Primary ML model for attack classification using multiple decision trees for robust IDS prediction.",
    metrics: {
      Accuracy: "98.12%",
      Precision: "98.17%",
      "F1 Score": "98.13%",
      Recall: "98.12%",
    },
    note: "Excellent for high-dimensional network data",
  },
  {
    name: "SVM Classifier",
    badge: "Anomaly Boundary",
    score: "97.86%",
    color: "blue",
    description:
      "Detects suspicious traffic patterns by separating normal and malicious behavior boundaries.",
    metrics: {
      Accuracy: "97.86%",
      Precision: "97.91%",
      "F1 Score": "97.88%",
      Recall: "97.84%",
    },
    note: "Useful for anomaly-based detection",
  },
  {
    name: "Decision Tree",
    badge: "Explainable",
    score: "98.06%",
    color: "orange",
    description:
      "Provides clear decision paths for security analysts and helps explain why an alert was generated.",
    metrics: {
      Accuracy: "98.06%",
      Precision: "98.12%",
      "F1 Score": "98.07%",
      Recall: "98.06%",
    },
    note: "Explainable AI for security teams",
  },
];

const attackCategories = [
  { name: "Service Exploits", score: "98.48%", samples: "15,547 samples", icon: "🖥️", color: "green" },
  { name: "Brute Force Attacks", score: "98.14%", samples: "294 samples", icon: "🔑", color: "cyan" },
  { name: "DDoS Attacks", score: "98.05%", samples: "608 samples", icon: "🛡️", color: "yellow" },
  { name: "Botnet Activities", score: "97.82%", samples: "11,098 samples", icon: "🤖", color: "red" },
  { name: "Port Scanning", score: "97.58%", samples: "2,031 samples", icon: "🔍", color: "blue" },
  { name: "Privilege Escalation", score: "89.80%", samples: "88 samples", icon: "⬆️", color: "gray" },
];

const stats = [
  { value: "98.1%", label: "Overall Accuracy" },
  { value: "6", label: "Attack Categories" },
  { value: "29,966", label: "Training Samples" },
  { value: "37", label: "Network Features" },
];

const datasetPoints = [
  "29,966 total training samples",
  "37 network traffic features",
  "6 attack categories + Normal traffic",
  "98.13% F1 Score achieved",
  "Balanced class distribution",
  "Production-ready performance",
];

const techStack = [
  "Python 3.9+",
  "Scikit-learn",
  "Pandas / NumPy",
  "Flask ML Service",
  "Random Forest",
  "SVM",
  "MongoDB",
  "React.js",
];

const features = [
  "Real-time network monitoring",
  "CSV dataset attack analysis",
  "HIDS and NIDS telemetry support",
  "ML-based attack classification",
  "Rule-based detection engine",
  "Live alerts and incident workflow",
];

const Overview = () => {
  return (
    <MainLayout>
      <div className="tl-overview-page">
        <section className="tl-overview-hero">
          <div className="tl-hero-shield">🛡️</div>
          <h1>ThreatLens IDS with Machine Learning</h1>
          <h3>Hybrid Intrusion Detection & Real-Time Security Monitoring</h3>
          <p>
            Protect your system and network with a hybrid IDS platform using Random Forest,
            SVM, rule-based detection, live telemetry, and real-time cyber threat monitoring.
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
          <h2>Ensemble Machine Learning Model</h2>
          <p>Production-ready algorithms for network intrusion detection</p>
          <span>Ensemble Model: Random Forest + SVM + Decision Tree</span>
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
            <h2>Targeted Attack Categories Performance</h2>
            <p>F1-score performance across different cyber attack types</p>
          </div>

          <div className="tl-attack-grid">
            {attackCategories.map((attack) => (
              <div key={attack.name} className={`tl-attack-card tl-border-${attack.color}`}>
                <div className="tl-attack-icon">{attack.icon}</div>
                <h3>{attack.name}</h3>
                <strong>{attack.score}</strong>
                <span>{attack.samples}</span>
              </div>
            ))}
          </div>

          <div className="tl-stats-grid">
            {stats.map((item) => (
              <div key={item.label} className="tl-stat-card">
                <strong>{item.value}</strong>
                <span>{item.label}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="tl-info-grid">
          <div className="tl-info-card tl-dataset-card">
            <h2>Training Dataset</h2>
            <p>
              ThreatLens uses structured network and host telemetry for accurate intrusion
              detection, classification, and alert generation.
            </p>

            <ul>
              {datasetPoints.map((point) => (
                <li key={point}>{point}</li>
              ))}
            </ul>
          </div>

          <div className="tl-info-card tl-tech-card">
            <h2>Technology Stack</h2>
            <p>
              Developed with modern full-stack and machine learning technologies for
              scalability, detection accuracy, and real-time visibility.
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
          <p>ThreatLens combines cybersecurity monitoring, ML prediction, and analyst workflow.</p>
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