import { useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import ThreatMapVisualization from "../components/threat-map/ThreatMapVisualization";
import ThreatMapSidebar from "../components/threat-map/ThreatMapSidebar";
import { generateAttack, generateAttackBatch } from "../components/threat-map/attackGenerator";
import "../components/threat-map/threatMap.css";

const MAX_ATTACKS = 60;

const ThreatMap = () => {
  const [attacks, setAttacks] = useState(() => generateAttackBatch(28));
  const [highlightedAttackId, setHighlightedAttackId] = useState(null);
  const [intervalLabel, setIntervalLabel] = useState("1 hour");
  const timeoutRef = useRef(null);

  useEffect(() => {
    const scheduleAttack = () => {
      const delay = 2000 + Math.floor(Math.random() * 1000);

      timeoutRef.current = window.setTimeout(() => {
        setAttacks((current) => [generateAttack(), ...current].slice(0, MAX_ATTACKS));
        scheduleAttack();
      }, delay);
    };

    scheduleAttack();

    return () => {
      if (timeoutRef.current) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const headline = useMemo(() => {
    const latest = attacks[0];

    if (!latest) {
      return "No active attacks in the feed.";
    }

    return `${latest.attackType} from ${latest.source.country} targeting ${latest.target.country}`;
  }, [attacks]);

  const counts = useMemo(() => {
    return attacks.reduce(
      (summary, attack) => {
        summary.total += 1;
        summary.bySeverity[attack.severity] += 1;
        return summary;
      },
      {
        total: 0,
        bySeverity: { low: 0, medium: 0, high: 0 },
      }
    );
  }, [attacks]);

  return (
    <MainLayout>
      <section className="threat-map-page">
        <div className="threat-map-header">
          <div>
            <span className="threat-map-eyebrow">ThreatLens / Global telemetry / live attack stream</span>
            <h1>Live Cyber Threat Map</h1>
            <p>{headline}</p>
          </div>
          <div className="threat-map-header-actions">
            <div className="threat-map-stat-chip">
              <span>Total attacks</span>
              <strong>{counts.total}</strong>
            </div>
            <div className="threat-map-stat-chip threat-map-stat-chip-danger">
              <span>High severity</span>
              <strong>{counts.bySeverity.high}</strong>
            </div>
            <label className="threat-map-interval">
              <span>Statistics Interval</span>
              <select
                value={intervalLabel}
                onChange={(event) => setIntervalLabel(event.target.value)}
              >
                <option>15 min</option>
                <option>1 hour</option>
                <option>6 hours</option>
              </select>
            </label>
          </div>
        </div>

        <div className="threat-map-layout">
          <ThreatMapVisualization
            attacks={attacks}
            highlightedAttackId={highlightedAttackId}
            onHighlight={setHighlightedAttackId}
          />
          <ThreatMapSidebar
            attacks={attacks}
            intervalLabel={intervalLabel}
            highlightedAttackId={highlightedAttackId}
            onHighlight={setHighlightedAttackId}
          />
        </div>
      </section>
    </MainLayout>
  );
};

export default ThreatMap;
