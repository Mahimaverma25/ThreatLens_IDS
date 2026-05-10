import { useCallback, useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import ThreatMapVisualization from "../components/threat-map/ThreatMapVisualization";
import ThreatMapSidebar from "../components/threat-map/ThreatMapSidebar";
import { intel, logs } from "../services/api";
import useSocket from "../hooks/useSocket";
import "../components/threat-map/threatMap.css";

const INTERVALS = {
  "15 min": 15 * 60 * 1000,
  "1 hour": 60 * 60 * 1000,
  "6 hours": 6 * 60 * 60 * 1000,
};

const COUNTRY_POOL = [
  { country: "India", lat: 20.5937, lng: 78.9629 },
  { country: "United States", lat: 37.0902, lng: -95.7129 },
  { country: "Germany", lat: 51.1657, lng: 10.4515 },
  { country: "Singapore", lat: 1.3521, lng: 103.8198 },
  { country: "Japan", lat: 36.2048, lng: 138.2529 },
];

const safeArray = (value) => (Array.isArray(value) ? value : []);

const severityFromLog = (log) => {
  const value = String(
    log?.severity ||
      log?.metadata?.severity ||
      log?.metadata?.idsEngine?.severity ||
      ""
  ).toLowerCase();

  if (["critical", "high", "medium", "low"].includes(value)) return value;
  if (String(log?.message || "").toLowerCase().includes("process")) return "low";
  if (String(log?.message || "").toLowerCase().includes("heartbeat")) return "low";
  return "medium";
};

const buildAttackFromLog = (log, index) => {
  const source = COUNTRY_POOL[index % COUNTRY_POOL.length];
  const target = COUNTRY_POOL[0];

  return {
    id: log._id || log.eventId || `log-${index}`,
    attackType:
      log.metadata?.classification ||
      log.eventType ||
      log.message ||
      "Telemetry Event",
    severity: severityFromLog(log),
    riskScore:
      severityFromLog(log) === "high"
        ? 75
        : severityFromLog(log) === "medium"
          ? 45
          : 20,
    timestamp: log.timestamp || log.createdAt || new Date().toISOString(),
    source: {
      country: source.country,
      lat: source.lat,
      lng: source.lng,
      ip: log.ip || log.sourceIp || log.metadata?.sourceIp || "agent",
    },
    target: {
      country: target.country,
      lat: target.lat,
      lng: target.lng,
      ip: log.destinationIp || log.metadata?.destinationIp || "ThreatLens",
    },
    raw: log,
  };
};

const ThreatMap = () => {
  const [attacks, setAttacks] = useState([]);
  const [highlightedAttackId, setHighlightedAttackId] = useState(null);
  const [intervalLabel, setIntervalLabel] = useState("1 hour");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [streamStatus, setStreamStatus] = useState("connecting");

  const token = localStorage.getItem("accessToken");

  const fetchThreatMap = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [mapResponse, logsResponse] = await Promise.allSettled([
        intel.threatMap(),
        logs.list(80, 1),
      ]);

      const mapAttacks =
        mapResponse.status === "fulfilled"
          ? safeArray(mapResponse.value?.data?.data?.attacks)
          : [];

      const logRows =
        logsResponse.status === "fulfilled"
          ? safeArray(logsResponse.value?.data?.data)
          : [];

      const fallbackAttacks = logRows.map(buildAttackFromLog);

      setAttacks(mapAttacks.length ? mapAttacks : fallbackAttacks);
      setStreamStatus("live");
    } catch (fetchError) {
      console.error("Threat map error:", fetchError);
      setError("Failed to load threat activity map data");
      setStreamStatus("degraded");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreatMap();
  }, [fetchThreatMap]);

  useSocket(token, {
    "socket:ready": () => setStreamStatus("live"),
    "logs:new": fetchThreatMap,
    "log:new": fetchThreatMap,
    "dashboard:update": fetchThreatMap,
    "stream:event": fetchThreatMap,
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
      return "No active threat activity in the current telemetry feed.";
    }

    return `${latest.attackType} from ${latest.source?.country || "Unknown"} targeting ${
      latest.target?.country || "ThreatLens"
    }`;
  }, [visibleAttacks]);

  const counts = useMemo(() => {
    return visibleAttacks.reduce(
      (summary, attack) => {
        const severity = String(attack.severity || "low").toLowerCase();

        summary.total += 1;
        if (summary.bySeverity[severity] !== undefined) {
          summary.bySeverity[severity] += 1;
        }
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
        <div className="loading">Loading threat activity map...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="threat-map-page">
        <div className="threat-map-header">
          <div>
            <span className="threat-map-eyebrow">
              ThreatLens / Live telemetry / monitoring visualization
            </span>
            <h1>Threat Activity Map</h1>
            <p>{headline}</p>
          </div>

          <div className="threat-map-header-actions">
            <div className="threat-map-stat-chip">
              <span>Visible Events</span>
              <strong>{counts.total}</strong>
            </div>

            <div className="threat-map-stat-chip threat-map-stat-chip-danger">
              <span>High Severity</span>
              <strong>{counts.bySeverity.high}</strong>
            </div>

            <div className="threat-map-stat-chip">
              <span>Stream State</span>
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