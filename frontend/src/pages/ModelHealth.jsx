import { useCallback, useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, dashboard, intel, logs } from "../services/api";

const safeArray = (value) => (Array.isArray(value) ? value : []);

const normalizeStatus = (value) => {
  const normalized = String(value || "unknown").toLowerCase();
  if (normalized === "ok") return "online";
  return normalized;
};

const statusLabel = (value, offlineLabel = "Offline") => {
  const normalized = normalizeStatus(value);
  if (normalized === "online") return "Online";
  if (normalized === "offline") return offlineLabel;
  if (normalized === "disabled") return "Disabled";
  return "Unknown";
};

const percentText = (value) =>
  typeof value === "number" ? `${Math.round(value * 100)}%` : "Unavailable";

const decimalText = (value) =>
  typeof value === "number" ? value.toFixed(3) : "Unavailable";

const formatDateTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const getHealthClass = (status) => {
  const value = String(status || "").toLowerCase();
  if (value === "online" || value === "healthy") return "health-online";
  if (value === "offline" || value === "not active") return "health-offline";
  return "health-unknown";
};

const ModelHealth = () => {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [details, setDetails] = useState(null);
  const [alertList, setAlertList] = useState([]);
  const [logList, setLogList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const fetchModelHealth = useCallback(async (silent = false) => {
    try {
      silent ? setRefreshing(true) : setLoading(true);
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
        setError("Failed to load model health.");
      } else if (healthResponse.status === "rejected" || detailsResponse.status === "rejected") {
        setError("Model health is partially available. IDS engine details could not be fully loaded.");
      }
    } catch (fetchError) {
      setError("Failed to load model health.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchModelHealth();
  }, [fetchModelHealth]);

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
    const falsePositives = alertList.filter(
      (alert) => String(alert.status).toLowerCase() === "false positive"
    ).length;

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

  const hidsMetrics = useMemo(
    () => ({
      status: statusLabel(health?.host?.status, "Not active"),
      eventsLast24h: stats?.traffic?.hostEventsLast24h ?? 0,
      alertsLast24h: stats?.traffic?.hostAlertsLast24h ?? 0,
      lastEventAt: health?.host?.lastEventAt || null,
      collectorStatus: statusLabel(health?.collector?.status, "No heartbeat"),
      telemetryTypes: safeArray(health?.collector?.telemetryTypes),
    }),
    [health, stats]
  );

  const nidsMetrics = useMemo(
    () => ({
      status: statusLabel(health?.snort?.status, "Not active"),
      eventsLast24h: stats?.traffic?.liveSnortEventsLast24h ?? 0,
      alertsLast24h: stats?.traffic?.liveSnortAlertsLast24h ?? 0,
      lastEventAt: health?.snort?.lastEventAt || null,
      protocolCoverage: stats?.traffic?.telemetryCoverage?.withProtocol ?? 0,
      totalTelemetry: stats?.traffic?.telemetryCoverage?.total ?? 0,
    }),
    [health, stats]
  );

  const mlMetrics = useMemo(
    () => ({
      status: derived.modelStatus === "online" ? "Online" : "Offline",
      analyzedEvents: derived.mlAnalyzedEvents,
      anomaliesLast24h: stats?.traffic?.mlAnomaliesLast24h ?? 0,
      algorithm: derived.algorithm,
      trainedAt: idsEngine.trainedAt,
      message: idsEngine.error || idsEngine.message || "ML detection not active yet",
    }),
    [derived, idsEngine, stats]
  );

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Checking model health...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <style>{`
        .model-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background: linear-gradient(135deg, #fff7ed 0%, #f8fbff 55%, #eef9f1 100%);
        }

        .model-shell {
          max-width: 1240px;
          margin: 0 auto;
        }

        .model-header {
          display: flex;
          justify-content: space-between;
          gap: 22px;
          align-items: flex-start;
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 24px;
          padding: 30px;
          margin-bottom: 24px;
          box-shadow: 0 18px 45px rgba(15,23,42,.08);
        }

        .model-eyebrow {
          color: #0ea5e9;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: .12em;
          margin-bottom: 8px;
        }

        .model-header h1 {
          margin: 0;
          font-size: 34px;
          color: #0f2742;
        }

        .model-header p {
          margin: 10px 0 0;
          color: #64748b;
          line-height: 1.6;
          max-width: 760px;
        }

        .primary-btn {
          border: 0;
          border-radius: 14px;
          padding: 13px 18px;
          font-weight: 900;
          cursor: pointer;
          color: #fff;
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
          box-shadow: 0 12px 26px rgba(37,99,235,.22);
        }

        .primary-btn:disabled {
          opacity: .6;
          cursor: not-allowed;
        }

        .model-metrics {
          display: grid;
          grid-template-columns: repeat(5, minmax(0, 1fr));
          gap: 18px;
          margin-bottom: 22px;
        }

        .model-metric-card,
        .model-panel {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          box-shadow: 0 14px 34px rgba(15,23,42,.07);
        }

        .model-metric-card {
          border-radius: 20px;
          padding: 22px;
        }

        .model-metric-card span {
          display: block;
          font-size: 12px;
          color: #64748b;
          font-weight: 900;
          text-transform: uppercase;
          margin-bottom: 10px;
        }

        .model-metric-card strong {
          font-size: 26px;
          color: #0f2742;
          overflow-wrap: anywhere;
        }

        .model-metric-card small {
          display: block;
          color: #64748b;
          margin-top: 7px;
          line-height: 1.4;
        }

        .health-dot {
          display: inline-flex;
          align-items: center;
          gap: 8px;
        }

        .health-dot::before {
          content: "";
          width: 10px;
          height: 10px;
          border-radius: 999px;
          background: #94a3b8;
        }

        .health-online::before {
          background: #22c55e;
          box-shadow: 0 0 0 6px rgba(34,197,94,.12);
        }

        .health-offline::before {
          background: #ef4444;
          box-shadow: 0 0 0 6px rgba(239,68,68,.12);
        }

        .health-unknown::before {
          background: #f59e0b;
          box-shadow: 0 0 0 6px rgba(245,158,11,.12);
        }

        .model-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 22px;
        }

        .model-panel {
          border-radius: 24px;
          overflow: hidden;
        }

        .panel-wide {
          grid-column: 1 / -1;
        }

        .model-panel-header {
          padding: 22px 24px;
          border-bottom: 1px solid #eef2f7;
        }

        .model-panel-header h3 {
          margin: 0;
          color: #172033;
          font-size: 21px;
        }

        .model-panel-header span {
          display: block;
          margin-top: 6px;
          color: #64748b;
          font-size: 13px;
        }

        .model-list {
          padding: 18px 24px 24px;
          display: grid;
          gap: 12px;
        }

        .model-row {
          display: grid;
          grid-template-columns: 230px minmax(0, 1fr);
          gap: 14px;
          align-items: center;
          background: #f8fbff;
          border: 1px solid #e2e8f0;
          border-radius: 16px;
          padding: 14px 16px;
        }

        .model-row span {
          color: #64748b;
          font-weight: 800;
          font-size: 13px;
        }

        .model-row strong {
          color: #0f2742;
          overflow-wrap: anywhere;
          line-height: 1.5;
        }

        .feature-chip-wrap {
          display: flex;
          gap: 9px;
          flex-wrap: wrap;
        }

        .feature-chip {
          padding: 7px 10px;
          background: #eef6ff;
          color: #1d4ed8;
          border: 1px solid #dbeafe;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 900;
        }

        .error-message {
          background: #fff1f2;
          color: #be123c;
          border: 1px solid #fecdd3;
          border-radius: 14px;
          padding: 14px 16px;
          margin-bottom: 18px;
          font-weight: 800;
        }

        .model-note {
          margin-bottom: 22px;
          background: #eff6ff;
          color: #1e3a8a;
          border: 1px solid #bfdbfe;
          border-radius: 18px;
          padding: 16px 18px;
          line-height: 1.6;
        }

        @media (max-width: 1100px) {
          .model-metrics {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .model-grid {
            grid-template-columns: 1fr;
          }

          .model-row {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 700px) {
          .model-page {
            padding: 16px;
          }

          .model-header {
            flex-direction: column;
            padding: 24px;
          }

          .model-header h1 {
            font-size: 28px;
          }

          .model-metrics {
            grid-template-columns: 1fr;
          }

          .primary-btn {
            width: 100%;
          }
        }
      `}</style>

      <div className="model-page">
        <div className="model-shell">
          <section className="model-header">
            <div>
              <div className="model-eyebrow">
                ThreatLens / Detection Stack / Runtime Truth
              </div>
              <h1>Model Health</h1>
              <p>
                Track HIDS, NIDS, rule-based detection and ML engine separately so
                your dashboard shows what is actually active right now.
              </p>
            </div>

            <button
              type="button"
              className="primary-btn"
              onClick={() => fetchModelHealth(true)}
              disabled={refreshing}
            >
              {refreshing ? "Refreshing..." : "Refresh Health"}
            </button>
          </section>

          {error && <div className="error-message">{error}</div>}

          <div className="model-note">
            HIDS and NIDS can still collect events even if the ML engine is offline.
            When the IDS engine is offline, ThreatLens works in rule-based / ingest-only
            mode until the Python ML service becomes reachable again.
          </div>

          <section className="model-metrics">
            <div className="model-metric-card">
              <span>HIDS</span>
              <strong className={`health-dot ${getHealthClass(hidsMetrics.status)}`}>
                {hidsMetrics.status}
              </strong>
              <small>{hidsMetrics.eventsLast24h} host events / 24h</small>
            </div>

            <div className="model-metric-card">
              <span>NIDS</span>
              <strong className={`health-dot ${getHealthClass(nidsMetrics.status)}`}>
                {nidsMetrics.status}
              </strong>
              <small>{nidsMetrics.eventsLast24h} network events / 24h</small>
            </div>

            <div className="model-metric-card">
              <span>IDS Engine</span>
              <strong className={`health-dot ${getHealthClass(mlMetrics.status)}`}>
                {mlMetrics.status}
              </strong>
              <small>{mlMetrics.message}</small>
            </div>

            <div className="model-metric-card">
              <span>Database</span>
              <strong>{health?.database || "unknown"}</strong>
              <small>Persistence layer</small>
            </div>

            <div className="model-metric-card">
              <span>False Positive Rate</span>
              <strong>{derived.falsePositiveRate}%</strong>
              <small>Across current alerts</small>
            </div>
          </section>

          <section className="model-grid">
            <div className="model-panel">
              <div className="model-panel-header">
                <h3>HIDS Health</h3>
                <span>Host monitoring, endpoint telemetry and collector heartbeat</span>
              </div>

              <div className="model-list">
                <div className="model-row"><span>Status</span><strong>{hidsMetrics.status}</strong></div>
                <div className="model-row"><span>Collector</span><strong>{hidsMetrics.collectorStatus}</strong></div>
                <div className="model-row"><span>Host Events 24h</span><strong>{hidsMetrics.eventsLast24h}</strong></div>
                <div className="model-row"><span>Host Alerts 24h</span><strong>{hidsMetrics.alertsLast24h}</strong></div>
                <div className="model-row"><span>Last Host Event</span><strong>{formatDateTime(hidsMetrics.lastEventAt)}</strong></div>
                <div className="model-row">
                  <span>Telemetry Types</span>
                  <strong>{hidsMetrics.telemetryTypes.join(", ") || "host"}</strong>
                </div>
              </div>
            </div>

            <div className="model-panel">
              <div className="model-panel-header">
                <h3>NIDS Health</h3>
                <span>Snort / network IDS activity and protocol enrichment</span>
              </div>

              <div className="model-list">
                <div className="model-row"><span>Status</span><strong>{nidsMetrics.status}</strong></div>
                <div className="model-row"><span>Network Events 24h</span><strong>{nidsMetrics.eventsLast24h}</strong></div>
                <div className="model-row"><span>Network Alerts 24h</span><strong>{nidsMetrics.alertsLast24h}</strong></div>
                <div className="model-row"><span>Last NIDS Event</span><strong>{formatDateTime(nidsMetrics.lastEventAt)}</strong></div>
                <div className="model-row">
                  <span>Protocol Enrichment</span>
                  <strong>{nidsMetrics.protocolCoverage} / {nidsMetrics.totalTelemetry}</strong>
                </div>
                <div className="model-row">
                  <span>Current State</span>
                  <strong>
                    {nidsMetrics.eventsLast24h > 0
                      ? "Receiving network telemetry"
                      : "Not active yet"}
                  </strong>
                </div>
              </div>
            </div>

            <div className="model-panel panel-wide">
              <div className="model-panel-header">
                <h3>ML / IDS Engine</h3>
                <span>Random Forest, SVM and fallback detection runtime</span>
              </div>

              <div className="model-list">
                <div className="model-row"><span>Status</span><strong>{mlMetrics.status}</strong></div>
                <div className="model-row"><span>Engine Reachable</span><strong>{idsEngine.reachable ? "Yes" : "No"}</strong></div>
                <div className="model-row"><span>Algorithm</span><strong>{mlMetrics.algorithm}</strong></div>
                <div className="model-row">
                  <span>Model Loaded</span>
                  <strong>{derived.modelLoaded === null ? "Unknown" : derived.modelLoaded ? "Yes" : "No"}</strong>
                </div>
                <div className="model-row">
                  <span>Fallback Active</span>
                  <strong>{derived.usingFallback === null ? "Unknown" : derived.usingFallback ? "Yes" : "No"}</strong>
                </div>
                <div className="model-row"><span>ML Analyzed Events</span><strong>{mlMetrics.analyzedEvents}</strong></div>
                <div className="model-row"><span>ML Anomalies 24h</span><strong>{mlMetrics.anomaliesLast24h}</strong></div>
                <div className="model-row"><span>Trained At</span><strong>{formatDateTime(mlMetrics.trainedAt)}</strong></div>
                <div className="model-row"><span>Current Message</span><strong>{mlMetrics.message}</strong></div>
                <div className="model-row">
                  <span>Operating Mode</span>
                  <strong>{mlMetrics.status === "Offline" ? "Rule-based / ingest only" : "Hybrid ML active"}</strong>
                </div>
              </div>
            </div>

            <div className="model-panel panel-wide">
              <div className="model-panel-header">
                <h3>Submodel Details</h3>
                <span>Training metrics and model-loading status from IDS engine</span>
              </div>

              <div className="model-list">
                <div className="model-row"><span>RF Loaded</span><strong>{idsEngine.rfModel?.loaded ? "Yes" : "No"}</strong></div>
                <div className="model-row"><span>RF Accuracy</span><strong>{percentText(idsEngine.rfModel?.training_summary?.accuracy)}</strong></div>
                <div className="model-row"><span>RF Precision</span><strong>{percentText(idsEngine.rfModel?.training_summary?.precision)}</strong></div>
                <div className="model-row"><span>RF Recall</span><strong>{percentText(idsEngine.rfModel?.training_summary?.recall)}</strong></div>
                <div className="model-row"><span>RF F1 Score</span><strong>{percentText(idsEngine.rfModel?.training_summary?.f1_score)}</strong></div>
                <div className="model-row"><span>SVM Loaded</span><strong>{idsEngine.svmModel?.loaded ? "Yes" : "No"}</strong></div>
                <div className="model-row"><span>SVM Score Mean</span><strong>{decimalText(idsEngine.svmModel?.training_summary?.score_mean)}</strong></div>
                <div className="model-row"><span>Legacy Loaded</span><strong>{idsEngine.legacyModel?.loaded ? "Yes" : "No"}</strong></div>
                <div className="model-row"><span>Legacy Score Mean</span><strong>{decimalText(idsEngine.legacyModel?.training_summary?.score_mean)}</strong></div>
                <div className="model-row"><span>RF Samples</span><strong>{idsEngine.rfModel?.training_summary?.samples ?? 0}</strong></div>
                <div className="model-row"><span>RF Classes</span><strong>{safeArray(idsEngine.rfModel?.class_names).join(", ") || "Unavailable"}</strong></div>
                <div className="model-row">
                  <span>Features</span>
                  <strong>
                    <div className="feature-chip-wrap">
                      {idsEngine.featureNames.length ? (
                        idsEngine.featureNames.slice(0, 20).map((feature) => (
                          <span className="feature-chip" key={feature}>{feature}</span>
                        ))
                      ) : (
                        "Unavailable"
                      )}
                    </div>
                  </strong>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </MainLayout>
  );
};

export default ModelHealth;