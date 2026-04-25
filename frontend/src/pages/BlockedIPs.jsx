import { useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { alerts, logs } from "../services/api";

const normalizeIp = (value) => String(value || "").trim();

const isValidIp = (value) => {
  const ip = normalizeIp(value);
  const ipv4 =
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  return ipv4.test(ip);
};

const formatTime = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

const getLogSourceIp = (log) =>
  log?.metadata?.snort?.srcIp ||
  log?.metadata?.sourceIp ||
  log?.src_ip ||
  log?.source_ip ||
  log?.ip ||
  "";

const getLogDestIp = (log) =>
  log?.metadata?.snort?.destIp ||
  log?.metadata?.destinationIp ||
  log?.dst_ip ||
  log?.destination_ip ||
  "";

const getAttackType = (item = {}) =>
  item.attackType ||
  item.attack_type ||
  item.event_type ||
  item.category ||
  item.rule ||
  item.message ||
  "Suspicious Activity";

const defaultManualBlock = {
  ip: "",
  attackType: "Manual Block",
  severity: "high",
  reason: "",
};

const BlockedIPs = () => {
  const [entries, setEntries] = useState([]);
  const [unblockedHistory, setUnblockedHistory] = useState([]);
  const [manualBlock, setManualBlock] = useState(defaultManualBlock);
  const [loading, setLoading] = useState(true);
  const [manualError, setManualError] = useState("");
  const [error, setError] = useState("");

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
        const ip = normalizeIp(alert.ip || alert.src_ip || alert.source_ip || alert.sourceIp);
        if (!ip) return;

        const severity = String(alert.severity || "low").toLowerCase();
        const current = ipMap.get(ip) || {
          ip,
          alertCount: 0,
          logCount: 0,
          highestSeverity: "low",
          latestTimestamp: null,
          attackTypes: new Set(),
          manual: false,
          reason: "",
        };

        current.alertCount += 1;
        current.latestTimestamp = alert.timestamp || alert.createdAt || current.latestTimestamp;
        current.attackTypes.add(getAttackType(alert));

        if (severityRank[severity] > severityRank[current.highestSeverity]) {
          current.highestSeverity = severity;
        }

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
            attackTypes: new Set(),
            manual: false,
            reason: "",
          };

          current.logCount += 1;
          current.latestTimestamp = log.timestamp || log.createdAt || current.latestTimestamp;
          current.attackTypes.add(getAttackType(log));

          ipMap.set(ip, current);
        });
      });

      const derivedEntries = Array.from(ipMap.values())
        .map((item) => {
          const blockCount = item.alertCount * 5 + item.logCount;
          const status =
            item.alertCount >= 3 || item.highestSeverity === "critical"
              ? "Blocked"
              : item.alertCount >= 1
                ? "Watchlist"
                : "Observed";

          return {
            ...item,
            blockCount,
            status,
            attackType: Array.from(item.attackTypes)[0] || "Suspicious Activity",
          };
        })
        .sort((a, b) => b.blockCount - a.blockCount)
        .slice(0, 25);

      setEntries((current) => {
        const manualEntries = current.filter((entry) => entry.manual && entry.status === "Blocked");
        const derivedWithoutManualDuplicates = derivedEntries.filter(
          (entry) => !manualEntries.some((manual) => manual.ip === entry.ip)
        );

        return [...manualEntries, ...derivedWithoutManualDuplicates];
      });
    } catch (fetchError) {
      console.error("Blocked IPs error:", fetchError);
      setError(fetchError?.response?.data?.message || "Failed to load blocked IP view.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlockedCandidates();
  }, []);

  const currentlyBlocked = entries.filter((entry) => entry.status === "Blocked");
  const watchlist = entries.filter((entry) => entry.status === "Watchlist");
  const observed = entries.filter((entry) => entry.status === "Observed");

  const summary = useMemo(
    () => ({
      blocked: currentlyBlocked.length,
      manual: currentlyBlocked.filter((entry) => entry.manual).length,
      watchlist: watchlist.length,
      observed: observed.length,
      total: entries.length,
    }),
    [currentlyBlocked, watchlist.length, observed.length, entries.length]
  );

  const handleManualBlock = (event) => {
    event.preventDefault();
    setManualError("");

    const ip = normalizeIp(manualBlock.ip);

    if (!isValidIp(ip)) {
      setManualError("Please enter a valid IPv4 address, for example 192.168.1.10.");
      return;
    }

    const exists = entries.some((entry) => entry.ip === ip && entry.status === "Blocked");
    if (exists) {
      setManualError("This IP is already blocked.");
      return;
    }

    const now = new Date().toISOString();

    setEntries((current) => {
      const withoutSameIp = current.filter((entry) => entry.ip !== ip);

      return [
        {
          ip,
          alertCount: 1,
          logCount: 0,
          highestSeverity: manualBlock.severity,
          latestTimestamp: now,
          attackType: manualBlock.attackType,
          blockCount: 1,
          status: "Blocked",
          manual: true,
          reason: manualBlock.reason || "Blocked manually by analyst",
          attackTypes: new Set([manualBlock.attackType]),
        },
        ...withoutSameIp,
      ];
    });

    setManualBlock(defaultManualBlock);
  };

  const handleUnblock = (ip) => {
    const selected = entries.find((entry) => entry.ip === ip);
    if (!selected) return;

    setEntries((current) =>
      current.map((entry) =>
        entry.ip === ip
          ? {
              ...entry,
              status: "Observed",
            }
          : entry
      )
    );

    setUnblockedHistory((current) => [
      {
        ...selected,
        unblockedAt: new Date().toISOString(),
      },
      ...current,
    ]);
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading blocked IPs...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="tl-blocked-page">
        <section className="tl-blocked-header">
          <div>
            <h1>🛡️ Blocked IPs Management</h1>
            <p>
              Review IPs detected from ThreatLens alerts and logs, and manually block
              suspicious addresses when an analyst confirms hostile behavior.
            </p>
          </div>

          <button className="tl-blocked-refresh" type="button" onClick={fetchBlockedCandidates}>
            Refresh
          </button>
        </section>

        {error && <div className="error-message">{error}</div>}

        <section className="tl-blocked-summary">
          <div>
            <span>Currently Blocked</span>
            <strong>{summary.blocked}</strong>
          </div>
          <div>
            <span>Manual Blocks</span>
            <strong>{summary.manual}</strong>
          </div>
          <div>
            <span>Watchlist</span>
            <strong>{summary.watchlist}</strong>
          </div>
          <div>
            <span>Total IPs</span>
            <strong>{summary.total}</strong>
          </div>
        </section>

        <section className="tl-manual-block-panel">
          <div className="tl-ip-panel-title">
            <span>➕ Manually Block IP</span>
          </div>

          <form className="tl-manual-block-form" onSubmit={handleManualBlock}>
            <div className="tl-form-group">
              <label>IP Address</label>
              <input
                type="text"
                placeholder="Example: 192.168.1.10"
                value={manualBlock.ip}
                onChange={(event) =>
                  setManualBlock({ ...manualBlock, ip: event.target.value })
                }
              />
            </div>

            <div className="tl-form-group">
              <label>Attack Type</label>
              <select
                value={manualBlock.attackType}
                onChange={(event) =>
                  setManualBlock({ ...manualBlock, attackType: event.target.value })
                }
              >
                <option value="Manual Block">Manual Block</option>
                <option value="Brute Force Attack">Brute Force Attack</option>
                <option value="DDoS Attack">DDoS Attack</option>
                <option value="Port Scan">Port Scan</option>
                <option value="Malware Activity">Malware Activity</option>
                <option value="Suspicious Login">Suspicious Login</option>
                <option value="Data Exfiltration">Data Exfiltration</option>
              </select>
            </div>

            <div className="tl-form-group">
              <label>Severity</label>
              <select
                value={manualBlock.severity}
                onChange={(event) =>
                  setManualBlock({ ...manualBlock, severity: event.target.value })
                }
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div className="tl-form-group">
              <label>Reason</label>
              <input
                type="text"
                placeholder="Why are you blocking this IP?"
                value={manualBlock.reason}
                onChange={(event) =>
                  setManualBlock({ ...manualBlock, reason: event.target.value })
                }
              />
            </div>

            <button className="tl-manual-block-btn" type="submit">
              Block IP
            </button>
          </form>

          {manualError && <div className="tl-manual-error">{manualError}</div>}
        </section>

        <section className="tl-ip-panel">
          <div className="tl-ip-panel-title">
            <span>⊘ Currently Blocked IPs ({currentlyBlocked.length})</span>
          </div>

          {currentlyBlocked.length ? (
            <div className="tl-ip-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Attack Type</th>
                    <th>Blocked At</th>
                    <th>Block Count</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Actions</th>
                  </tr>
                </thead>

                <tbody>
                  {currentlyBlocked.map((entry) => (
                    <tr key={entry.ip}>
                      <td className="tl-ip-address">{entry.ip}</td>
                      <td>
                        <span className="tl-attack-pill">{entry.attackType}</span>
                        {entry.reason ? <small className="tl-ip-reason">{entry.reason}</small> : null}
                      </td>
                      <td>{formatTime(entry.latestTimestamp)}</td>
                      <td>
                        <span className="tl-count-pill">{entry.blockCount}</span>
                      </td>
                      <td>
                        <span className={`tl-severity-pill ${entry.highestSeverity}`}>
                          {entry.highestSeverity}
                        </span>
                      </td>
                      <td>
                        <span className={entry.manual ? "tl-source-manual" : "tl-source-auto"}>
                          {entry.manual ? "Manual" : "Auto"}
                        </span>
                      </td>
                      <td>
                        <button
                          className="tl-unblock-btn"
                          type="button"
                          onClick={() => handleUnblock(entry.ip)}
                        >
                          Unblock
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="tl-ip-empty">No currently blocked IPs.</div>
          )}
        </section>

        <section className="tl-ip-panel">
          <div className="tl-ip-panel-title">
            <span>⚠ Watchlist IPs ({watchlist.length})</span>
          </div>

          {watchlist.length ? (
            <div className="tl-ip-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Attack Type</th>
                    <th>Latest Seen</th>
                    <th>Alert Hits</th>
                    <th>Telemetry Hits</th>
                    <th>Status</th>
                  </tr>
                </thead>

                <tbody>
                  {watchlist.map((entry) => (
                    <tr key={entry.ip}>
                      <td className="tl-ip-address">{entry.ip}</td>
                      <td>
                        <span className="tl-attack-pill warning">{entry.attackType}</span>
                      </td>
                      <td>{formatTime(entry.latestTimestamp)}</td>
                      <td>{entry.alertCount}</td>
                      <td>{entry.logCount}</td>
                      <td>
                        <span className="tl-watch-pill">{entry.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="tl-ip-empty">No watchlist IPs available.</div>
          )}
        </section>

        <section className="tl-ip-panel">
          <div className="tl-ip-panel-title">
            <span>◷ Recently Unblocked IPs</span>
          </div>

          {unblockedHistory.length ? (
            <div className="tl-ip-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Attack Type</th>
                    <th>Unblocked At</th>
                    <th>Previous Count</th>
                    <th>Source</th>
                  </tr>
                </thead>

                <tbody>
                  {unblockedHistory.map((entry) => (
                    <tr key={`${entry.ip}-${entry.unblockedAt}`}>
                      <td className="tl-ip-address">{entry.ip}</td>
                      <td>{entry.attackType}</td>
                      <td>{formatTime(entry.unblockedAt)}</td>
                      <td>{entry.blockCount}</td>
                      <td>{entry.manual ? "Manual" : "Auto"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="tl-ip-empty">No unblock history available.</div>
          )}
        </section>
      </div>
    </MainLayout>
  );
};

export default BlockedIPs;