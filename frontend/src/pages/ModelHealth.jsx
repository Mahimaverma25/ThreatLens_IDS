import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, intel, logs } from "../services/api";

const normalizeStatus = (value) => {
  const normalized = String(value || "unknown").toLowerCase();
  return normalized === "ok" ? "online" : normalized;
};

const percentText = (value) =>
  typeof value === "number" ? `${Math.round(value * 100)}%` : "Unavailable";

const decimalText = (value) =>
  typeof value === "number" ? value.toFixed(3) : "Unavailable";

const safeArray = (value) => (Array.isArray(value) ? value : []);

const formatDateTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const statusLabel = (value, offlineLabel = "Offline") => {
  const normalized = normalizeStatus(value);
  if (normalized === "online") return "Online";
  if (normalized === "offline") return offlineLabel;
  if (normalized === "disabled") return "Disabled";
  return "Unknown";
};

const ModelHealth = () => {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [details, setDetails] = useState(null);
  const [alertList, setAlertList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchModelHealth = async () => {
      try {
        setLoading(true);
        setError("");

        const [healthResponse, statsResponse, alertsResponse, logsResponse, detailsResponse] =
          await Promise.allSettled([
            dashboard.health(),
            dashboard.stats(),
            alerts.list(120, 1),
            logs.list(120, 1),
            intel.modelHealth(),
          ]);

        setHealth(healthResponse.status === "fulfilled" ? healthResponse.value?.data ?? null : null);
        setStats(statsResponse.status === "fulfilled" ? statsResponse.value?.data ?? null : null);
        setAlertList(alertsResponse.status === "fulfilled" ? alertsResponse.value?.data?.data ?? [] : []);
        setLogList(logsResponse.status === "fulfilled" ? logsResponse.value?.data?.data ?? [] : []);
        setDetails(detailsResponse.status === "fulfilled" ? detailsResponse.value?.data?.data ?? null : null);

        const allFailed = [
          healthResponse,
          statsResponse,
          alertsResponse,
          logsResponse,
          detailsResponse,
        ].every((result) => result.status === "rejected");

        if (allFailed) {
          setError("Failed to load model health");
        } else if (healthResponse.status === "rejected" || detailsResponse.status === "rejected") {
          setError("Model health is partially available. IDS engine details could not be fully loaded.");
        }
      } catch (fetchError) {
        console.error("Model health error:", fetchError);
        setError("Failed to load model health");
      } finally {
        setLoading(false);
      }
    };

    fetchModelHealth();
  }, []);

  const idsEngine = useMemo(() => {
    const healthEngine = health?.idsEngine || {};
    const detailEngine = details?.idsEngine || {};

    return {
      status: healthEngine?.status || detailEngine?.status || "unknown",
      message: healthEngine?.message || detailEngine?.message || "",
      reachable:
        healthEngine?.reachable ??
        detailEngine?.reachable ??
        normalizeStatus(healthEngine?.status) !== "offline",
      algorithm: healthEngine?.algorithm || detailEngine?.algorithm || "Unavailable",
      modelLoaded: healthEngine?.modelLoaded ?? detailEngine?.modelLoaded ?? null,
      usingFallback: healthEngine?.usingFallback ?? detailEngine?.usingFallback ?? null,
      trainedAt: healthEngine?.trainedAt || detailEngine?.trainedAt || null,
      featureNames: safeArray(healthEngine?.featureNames || detailEngine?.featureNames),
      rfModel: healthEngine?.rfModel || detailEngine?.rfModel || null,
      svmModel: healthEngine?.svmModel || detailEngine?.svmModel || null,
      legacyModel: healthEngine?.legacyModel || detailEngine?.legacyModel || null,
      error: healthEngine?.error || detailEngine?.error || "",
    };
  }, [details, health]);

  const derived = useMemo(() => {
    const falsePositives = alertList.filter((alert) => alert.status === "False Positive").length;
    const totalAlerts = alertList.length || 1;
    const mlAnalyzedEvents = logList.filter((log) => Boolean(log.metadata?.idsEngine)).length;

    return {
      falsePositives,
      falsePositiveRate: Math.round((falsePositives / totalAlerts) * 100),
      mlAnalyzedEvents,
      modelStatus: normalizeStatus(idsEngine.status),
      algorithm: idsEngine.algorithm || "Unavailable",
      modelLoaded:
        idsEngine.modelLoaded === null || idsEngine.modelLoaded === undefined
          ? null
          : Boolean(idsEngine.modelLoaded),
      usingFallback:
        idsEngine.usingFallback === null || idsEngine.usingFallback === undefined
          ? null
          : Boolean(idsEngine.usingFallback),
    };
  }, [alertList, idsEngine, logList]);

  const hidsMetrics = useMemo(() => ({
    status: statusLabel(health?.host?.status, "Not active"),
    eventsLast24h: stats?.traffic?.hostEventsLast24h ?? 0,
    alertsLast24h: stats?.traffic?.hostAlertsLast24h ?? 0,
    lastEventAt: health?.host?.lastEventAt || null,
    collectorStatus: statusLabel(health?.collector?.status, "No heartbeat"),
    telemetryTypes: safeArray(health?.collector?.telemetryTypes),
  }), [health, stats]);

  const nidsMetrics = useMemo(() => ({
    status: statusLabel(health?.snort?.status, "Not active"),
    eventsLast24h: stats?.traffic?.liveSnortEventsLast24h ?? 0,
    alertsLast24h: stats?.traffic?.liveSnortAlertsLast24h ?? 0,
    lastEventAt: health?.snort?.lastEventAt || null,
    protocolCoverage: stats?.traffic?.telemetryCoverage?.withProtocol ?? 0,
    totalTelemetry: stats?.traffic?.telemetryCoverage?.total ?? 0,
  }), [health, stats]);

  const mlMetrics = useMemo(() => ({
    status: derived.modelStatus === "online" ? "Online" : "Offline",
    analyzedEvents: derived.mlAnalyzedEvents,
    anomaliesLast24h: stats?.traffic?.mlAnomaliesLast24h ?? 0,
    algorithm: derived.algorithm,
    trainedAt: idsEngine.trainedAt,
    message: idsEngine.error || idsEngine.message || "ML detection not active yet",
  }), [derived.algorithm, derived.mlAnalyzedEvents, derived.modelStatus, idsEngine.error, idsEngine.message, idsEngine.trainedAt, stats]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Checking model health...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Detection stack / runtime truth</div>
          <h1>Model Health</h1>
          <p>Track HIDS, NIDS, and ML detection separately so the platform reflects what is actually active right now.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>HIDS</span>
          <strong>{hidsMetrics.status}</strong>
          <small>{hidsMetrics.eventsLast24h} host events / 24h</small>
        </div>
        <div className="metric-card">
          <span>NIDS</span>
          <strong>{nidsMetrics.status}</strong>
          <small>{nidsMetrics.eventsLast24h} network events / 24h</small>
        </div>
        <div className="metric-card">
          <span>IDS Engine</span>
          <strong>{mlMetrics.status}</strong>
          <small>{mlMetrics.message}</small>
        </div>
        <div className="metric-card">
          <span>Database</span>
          <strong>{health?.database || "unknown"}</strong>
          <small>Persistence layer</small>
        </div>
        <div className="metric-card">
          <span>False Positive Rate</span>
          <strong>{derived.falsePositiveRate}%</strong>
          <small>Across current alerts</small>
        </div>
      </section>

      <div className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>HIDS Health</h3>
            <span>Host monitoring only</span>
          </div>
          <div className="panel-list">
            <div className="list-row"><span>Status</span><strong>{hidsMetrics.status}</strong></div>
            <div className="list-row"><span>Collector</span><strong>{hidsMetrics.collectorStatus}</strong></div>
            <div className="list-row"><span>Host Events (24h)</span><strong>{hidsMetrics.eventsLast24h}</strong></div>
            <div className="list-row"><span>Host Alerts (24h)</span><strong>{hidsMetrics.alertsLast24h}</strong></div>
            <div className="list-row"><span>Last Host Event</span><strong>{formatDateTime(hidsMetrics.lastEventAt)}</strong></div>
            <div className="list-row"><span>Telemetry Types</span><strong>{hidsMetrics.telemetryTypes.join(", ") || "host"}</strong></div>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h3>NIDS Health</h3>
            <span>Protocol enrichment and network IDS</span>
          </div>
          <div className="panel-list">
            <div className="list-row"><span>Status</span><strong>{nidsMetrics.status}</strong></div>
            <div className="list-row"><span>Network Events (24h)</span><strong>{nidsMetrics.eventsLast24h}</strong></div>
            <div className="list-row"><span>Network Alerts (24h)</span><strong>{nidsMetrics.alertsLast24h}</strong></div>
            <div className="list-row"><span>Last NIDS Event</span><strong>{formatDateTime(nidsMetrics.lastEventAt)}</strong></div>
            <div className="list-row"><span>Protocol Enrichment</span><strong>{nidsMetrics.protocolCoverage} / {nidsMetrics.totalTelemetry}</strong></div>
            <div className="list-row"><span>Current State</span><strong>{nidsMetrics.eventsLast24h > 0 ? "Receiving network telemetry" : "Not active yet"}</strong></div>
          </div>
        </div>

        <div className="dashboard-panel panel-wide">
          <div className="panel-header">
            <h3>ML / IDS Engine</h3>
            <span>Separate from HIDS and NIDS runtime</span>
          </div>
          <div className="panel-list">
            <div className="list-row"><span>Status</span><strong>{mlMetrics.status}</strong></div>
            <div className="list-row"><span>Engine Reachable</span><strong>{idsEngine.reachable ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>Algorithm</span><strong>{mlMetrics.algorithm}</strong></div>
            <div className="list-row"><span>Model Loaded</span><strong>{derived.modelLoaded === null ? "Unknown" : derived.modelLoaded ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>Fallback Active</span><strong>{derived.usingFallback === null ? "Unknown" : derived.usingFallback ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>ML Analyzed Events</span><strong>{mlMetrics.analyzedEvents}</strong></div>
            <div className="list-row"><span>ML Anomalies (24h)</span><strong>{mlMetrics.anomaliesLast24h}</strong></div>
            <div className="list-row"><span>Trained At</span><strong>{formatDateTime(mlMetrics.trainedAt)}</strong></div>
            <div className="list-row"><span>Current Message</span><strong>{mlMetrics.message}</strong></div>
            <div className="list-row"><span>Operating Mode</span><strong>{mlMetrics.status === "Offline" ? "Rule-based / ingest only" : "Hybrid ML active"}</strong></div>
          </div>
        </div>

        <div className="dashboard-panel panel-wide">
          <div className="panel-header">
            <h3>Submodel Details</h3>
            <span>Only relevant when IDS engine is online</span>
          </div>
          <div className="panel-list">
            <div className="list-row"><span>RF Loaded</span><strong>{idsEngine.rfModel?.loaded ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>RF Accuracy</span><strong>{percentText(idsEngine.rfModel?.training_summary?.accuracy)}</strong></div>
            <div className="list-row"><span>RF Precision</span><strong>{percentText(idsEngine.rfModel?.training_summary?.precision)}</strong></div>
            <div className="list-row"><span>RF Recall</span><strong>{percentText(idsEngine.rfModel?.training_summary?.recall)}</strong></div>
            <div className="list-row"><span>RF F1</span><strong>{percentText(idsEngine.rfModel?.training_summary?.f1_score)}</strong></div>
            <div className="list-row"><span>SVM Loaded</span><strong>{idsEngine.svmModel?.loaded ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>SVM Score Mean</span><strong>{decimalText(idsEngine.svmModel?.training_summary?.score_mean)}</strong></div>
            <div className="list-row"><span>Legacy Loaded</span><strong>{idsEngine.legacyModel?.loaded ? "Yes" : "No"}</strong></div>
            <div className="list-row"><span>Legacy Score Mean</span><strong>{decimalText(idsEngine.legacyModel?.training_summary?.score_mean)}</strong></div>
            <div className="list-row"><span>RF Samples</span><strong>{idsEngine.rfModel?.training_summary?.samples ?? 0}</strong></div>
            <div className="list-row"><span>RF Classes</span><strong>{safeArray(idsEngine.rfModel?.class_names).join(", ") || "Unavailable"}</strong></div>
            <div className="list-row"><span>Confusion Matrix</span><strong>{idsEngine.rfModel?.training_summary?.confusion_matrix ? JSON.stringify(idsEngine.rfModel.training_summary.confusion_matrix) : "Unavailable"}</strong></div>
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default ModelHealth;
