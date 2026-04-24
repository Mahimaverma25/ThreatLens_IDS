import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, logs } from "../services/api";

const normalizeIp = (value) => String(value || "").trim();

const getLogSourceIp = (log) =>
  log?.metadata?.snort?.srcIp ||
  log?.metadata?.sourceIp ||
  log?.ip ||
  "";

const getLogDestIp = (log) =>
  log?.metadata?.snort?.destIp ||
  log?.metadata?.destinationIp ||
  "";

const BlockedIPs = () => {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchBlockedCandidates = async () => {
      try {
        setLoading(true);
        setError("");

        const [alertsResponse, logsResponse] = await Promise.all([
          alerts.list(150, 1),
          logs.list(200, 1),
        ]);

        const alertItems = alertsResponse?.data?.data ?? [];
        const logItems = logsResponse?.data?.data ?? [];
        const ipMap = new Map();

        alertItems.forEach((alert) => {
          const ip = normalizeIp(alert.ip || alert.src_ip || alert.source_ip);
          if (!ip) return;

          const current = ipMap.get(ip) || {
            ip,
            alertCount: 0,
            logCount: 0,
            highestSeverity: "low",
            latestTimestamp: null,
            source: "alerts",
          };

          current.alertCount += 1;
          current.latestTimestamp = alert.timestamp || current.latestTimestamp;
          current.highestSeverity =
            ["critical", "high", "medium", "low"].indexOf(String(alert.severity || "").toLowerCase()) <
            ["critical", "high", "medium", "low"].indexOf(String(current.highestSeverity || "").toLowerCase())
              ? alert.severity
              : current.highestSeverity;
          ipMap.set(ip, current);
        });

        logItems.forEach((log) => {
          [getLogSourceIp(log), getLogDestIp(log)].forEach((rawIp) => {
            const ip = normalizeIp(rawIp);
            if (!ip || ip === "-") return;

            const current = ipMap.get(ip) || {
              ip,
              alertCount: 0,
              logCount: 0,
              highestSeverity: "low",
              latestTimestamp: null,
              source: "telemetry",
            };

            current.logCount += 1;
            current.latestTimestamp = log.timestamp || current.latestTimestamp;
            ipMap.set(ip, current);
          });
        });

        const nextEntries = Array.from(ipMap.values())
          .map((item) => ({
            ...item,
            status:
              item.alertCount >= 3 || item.highestSeverity === "critical"
                ? "Blocked"
                : item.alertCount >= 1
                  ? "Watchlist"
                  : "Observed",
          }))
          .sort((left, right) => {
            const leftScore = left.alertCount * 5 + left.logCount;
            const rightScore = right.alertCount * 5 + right.logCount;
            return rightScore - leftScore;
          })
          .slice(0, 25);

        setEntries(nextEntries);
      } catch (fetchError) {
        console.error("Blocked IPs error:", fetchError);
        setError(fetchError?.response?.data?.message || "Failed to load blocked IP view.");
      } finally {
        setLoading(false);
      }
    };

    fetchBlockedCandidates();
  }, []);

  const summary = useMemo(
    () => ({
      blocked: entries.filter((entry) => entry.status === "Blocked").length,
      watchlist: entries.filter((entry) => entry.status === "Watchlist").length,
      observed: entries.filter((entry) => entry.status === "Observed").length,
    }),
    [entries]
  );

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading blocked IP candidates...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Network controls / IP watchlist</div>
          <h1>Blocked IPs</h1>
          <p>
            A live-derived IP review board built from alerts and telemetry so analysts can
            see which addresses are blocked, watched, or still being observed.
          </p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card danger">
          <span>Blocked</span>
          <strong>{summary.blocked}</strong>
        </div>
        <div className="metric-card warning">
          <span>Watchlist</span>
          <strong>{summary.watchlist}</strong>
        </div>
        <div className="metric-card">
          <span>Observed</span>
          <strong>{summary.observed}</strong>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <div>
            <h2>IP Enforcement View</h2>
            <p>Derived from current alerts and recent network telemetry.</p>
          </div>
        </div>
        {entries.length ? (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Status</th>
                  <th>Alert Hits</th>
                  <th>Telemetry Hits</th>
                  <th>Highest Severity</th>
                  <th>Latest Seen</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.ip}>
                    <td className="ip-cell">{entry.ip}</td>
                    <td>{entry.status}</td>
                    <td>{entry.alertCount}</td>
                    <td>{entry.logCount}</td>
                    <td>{entry.highestSeverity}</td>
                    <td>{entry.latestTimestamp ? new Date(entry.latestTimestamp).toLocaleString() : "No data"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <h3>No suspicious IPs yet</h3>
            <p>Blocked and watchlisted IP candidates will appear when telemetry and alerts arrive.</p>
          </div>
        )}
      </section>
    </MainLayout>
  );
};

export default BlockedIPs;
