const getTopEntries = (attacks, selector) => {
  const counts = attacks.reduce((accumulator, attack) => {
    const key = selector(attack);
    accumulator[key] = (accumulator[key] || 0) + 1;
    return accumulator;
  }, {});

  return Object.entries(counts)
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 5);
};

const formatTime = (timestamp) =>
  new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const withPercentages = (entries) => {
  const total = entries.reduce((sum, entry) => sum + entry.value, 0) || 1;
  return entries.map((entry) => ({
    ...entry,
    percentage: Math.round((entry.value / total) * 100),
  }));
};

const ThreatMapSidebar = ({
  attacks,
  intervalLabel,
  streamStatus,
  maxRisk,
  highlightedAttackId,
  onHighlight,
}) => {
  const topAttackers = withPercentages(getTopEntries(attacks, (attack) => attack.source.country));
  const topTargets = withPercentages(getTopEntries(attacks, (attack) => attack.target.country));
  const attackTypes = withPercentages(getTopEntries(attacks, (attack) => attack.attackType));
  const topSensors = withPercentages(getTopEntries(attacks, (attack) => attack.sensorType || "unknown"));

  return (
    <aside className="threat-map-sidebar">
      <div className="threat-map-panel">
        <span className="threat-map-panel-kicker">Threat Summary</span>
        <h2>Live Cyber Threat Map</h2>
        <p>Leaflet-powered live attack telemetry with active origin and target hotspots from your detection pipeline.</p>
        <div className="threat-map-mini-meta">
          <span>Statistics interval</span>
          <strong>{intervalLabel}</strong>
        </div>
      </div>

      <div className="threat-map-grid">
        <div className="threat-map-metric">
          <span>Total Attacks</span>
          <strong>{attacks.length}</strong>
        </div>
        <div className="threat-map-metric">
          <span>High Severity</span>
          <strong>{attacks.filter((attack) => attack.severity === "high").length}</strong>
        </div>
        <div className="threat-map-metric">
          <span>Max Risk</span>
          <strong>{maxRisk}</strong>
        </div>
        <div className="threat-map-metric">
          <span>Stream Status</span>
          <strong>{streamStatus}</strong>
        </div>
      </div>

      <div className="threat-map-panel">
        <div className="threat-map-panel-head">
          <h3>Top Attacking Countries</h3>
        </div>
        <div className="threat-map-list">
          {topAttackers.map((entry) => (
            <div key={entry.label} className="threat-map-list-row">
              <span>{entry.label}</span>
              <strong>{entry.percentage}%</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="threat-map-panel">
        <div className="threat-map-panel-head">
          <h3>Top Targeted Countries</h3>
        </div>
        <div className="threat-map-list">
          {topTargets.map((entry) => (
            <div key={entry.label} className="threat-map-list-row">
              <span>{entry.label}</span>
              <strong>{entry.percentage}%</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="threat-map-panel">
        <div className="threat-map-panel-head">
          <h3>Sensor Distribution</h3>
        </div>
        <div className="threat-map-list">
          {topSensors.map((entry) => (
            <div key={entry.label} className="threat-map-list-row">
              <span>{entry.label}</span>
              <strong>{entry.percentage}%</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="threat-map-panel">
        <div className="threat-map-panel-head">
          <h3>Attack Type Distribution</h3>
        </div>
        <div className="threat-map-list">
          {attackTypes.map((entry) => (
            <div key={entry.label} className="threat-map-list-row">
              <span>{entry.label}</span>
              <strong>{entry.percentage}%</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="threat-map-panel threat-map-events">
        <div className="threat-map-panel-head">
          <h3>Latest Activity</h3>
        </div>
        <div className="threat-map-event-list">
          {attacks.slice(0, 9).map((attack) => (
            <button
              type="button"
              key={attack.id}
              className={`threat-map-event-card ${
                highlightedAttackId === attack.id ? "is-highlighted" : ""
              }`}
              onMouseEnter={() => onHighlight?.(attack.id)}
              onMouseLeave={() => onHighlight?.(null)}
            >
              <div className="threat-map-event-top">
                <span className={`threat-map-severity-pill ${attack.severity}`}>
                  {attack.severity}
                </span>
                <small>{formatTime(attack.timestamp)}</small>
              </div>
              <strong>{attack.attackType}</strong>
              <p>
                {attack.source.country} to {attack.target.country}
              </p>
              <p>{attack.vector}</p>
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
};

export default ThreatMapSidebar;
