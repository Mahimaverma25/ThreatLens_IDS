import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import ThreatMapVisualization from "../components/threat-map/ThreatMapVisualization";
import ThreatMapSidebar from "../components/threat-map/ThreatMapSidebar";
import { intel } from "../services/api";
import useSocket from "../hooks/useSocket";
import "../components/threat-map/threatMap.css";

const INTERVALS = {
  "15 min": 15 * 60 * 1000,
  "1 hour": 60 * 60 * 1000,
  "6 hours": 6 * 60 * 60 * 1000,
};

const ThreatMap = () => {
  const [attacks, setAttacks] = useState([]);
  const [highlightedAttackId, setHighlightedAttackId] = useState(null);
  const [intervalLabel, setIntervalLabel] = useState("1 hour");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [streamStatus, setStreamStatus] = useState("connecting");

  const token = localStorage.getItem("accessToken");

  useEffect(() => {
    const fetchThreatMap = async () => {
      try {
        setLoading(true);
        setError("");
        const response = await intel.threatMap();
        setAttacks(response?.data?.data?.attacks ?? []);
      } catch (fetchError) {
        console.error("Threat map error:", fetchError);
        setError("Failed to load threat map data");
      } finally {
        setLoading(false);
      }
    };

    fetchThreatMap();
  }, []);

  useSocket(token, {
    "socket:ready": () => setStreamStatus("live"),
    "stream:event": (event) => {
      if (event?.type !== "telemetry.batch.persisted") {
        return;
      }

      intel
        .threatMap()
        .then((response) => {
          setAttacks(response?.data?.data?.attacks ?? []);
          setStreamStatus("live");
        })
        .catch(() => {
          setStreamStatus("degraded");
        });
    },
  });

  const visibleAttacks = useMemo(() => {
    const windowMs = INTERVALS[intervalLabel] || INTERVALS["1 hour"];
    const cutoff = Date.now() - windowMs;

    return attacks
      .filter((attack) => {
        const timestamp = new Date(attack.timestamp).getTime();
        return Number.isFinite(timestamp) && timestamp >= cutoff;
      })
      .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp));
  }, [attacks, intervalLabel]);

  const headline = useMemo(() => {
    const latest = visibleAttacks[0];

    if (!latest) {
      return "No active attacks in the feed.";
    }

    return `${latest.attackType} from ${latest.source.country} targeting ${latest.target.country}`;
  }, [visibleAttacks]);

  const counts = useMemo(() => {
    return visibleAttacks.reduce(
      (summary, attack) => {
        summary.total += 1;
        summary.bySeverity[attack.severity] += 1;
        summary.maxRisk = Math.max(summary.maxRisk, Number(attack.riskScore || 0));
        return summary;
      },
      {
        total: 0,
        bySeverity: { low: 0, medium: 0, high: 0 },
        maxRisk: 0,
      }
    );
  }, [visibleAttacks]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading threat map...</div>
      </MainLayout>
    );
  }

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
              <span>Visible attacks</span>
              <strong>{counts.total}</strong>
            </div>
            <div className="threat-map-stat-chip threat-map-stat-chip-danger">
              <span>High severity</span>
              <strong>{counts.bySeverity.high}</strong>
            </div>
            <div className="threat-map-stat-chip">
              <span>Stream state</span>
              <strong>{streamStatus}</strong>
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

        {error && <div className="error-message">{error}</div>}

        <div className="threat-map-layout">
          <ThreatMapVisualization
            attacks={visibleAttacks}
            highlightedAttackId={highlightedAttackId}
            onHighlight={setHighlightedAttackId}
          />
          <ThreatMapSidebar
            attacks={visibleAttacks}
            intervalLabel={intervalLabel}
            streamStatus={streamStatus}
            maxRisk={counts.maxRisk}
            highlightedAttackId={highlightedAttackId}
            onHighlight={setHighlightedAttackId}
          />
        </div>
      </section>
    </MainLayout>
  );
};

export default ThreatMap;
