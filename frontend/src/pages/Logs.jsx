import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { logs } from "../services/api";
import useSocket from "../hooks/useSocket";

const resolveSocketLog = (payload) => payload?.data || payload;

const formatTimestamp = (value) => {
  if (!value) return "No data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No data" : date.toLocaleString();
};

const getProtocol = (log) =>
  log?.metadata?.protocol ||
  log?.metadata?.appProtocol ||
  log?.metadata?.snort?.protocol ||
  "Unknown";

const getClassification = (log) =>
  log?.metadata?.snort?.classification ||
  log?.metadata?.classification ||
  log?.eventType ||
  log?.source ||
  "-";

const getPriority = (log) =>
  log?.metadata?.snort?.priority ||
  log?.metadata?.priority ||
  log?.metadata?.idsEngine?.severity ||
  "-";

const getSourceIp = (log) =>
  log?.metadata?.snort?.srcIp ||
  log?.metadata?.sourceIp ||
  log?.src_ip ||
  log?.source_ip ||
  log?.ip ||
  "-";

const getDestinationIp = (log) =>
  log?.metadata?.snort?.destIp ||
  log?.metadata?.destinationIp ||
  log?.dst_ip ||
  log?.destination_ip ||
  "-";

const getDestinationPort = (log) =>
  log?.metadata?.destinationPort ||
  log?.metadata?.port ||
  log?.metadata?.snort?.destPort ||
  "-";

const getSourceName = (log) =>
  log?.metadata?.sensorType ||
  log?.source ||
  "unknown";

const priorityClass = (priority) => {
  const value = String(priority).toLowerCase();

  if (value === "1" || value === "critical") return "critical";
  if (value === "2" || value === "high") return "high";
  if (value === "3" || value === "medium") return "medium";
  return "low";
};

const matchesFilters = (log, filters) => {
  const protocol = String(getProtocol(log)).toUpperCase();
  const destinationPort = String(getDestinationPort(log));
  const source = String(getSourceName(log)).toLowerCase();

  const searchTarget = [
    log?.message,
    log?.eventType,
    getClassification(log),
    protocol,
    source,
    getSourceIp(log),
    getDestinationIp(log),
    getDestinationPort(log),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (filters.level && log?.level !== filters.level) return false;
  if (filters.source && source !== String(filters.source).toLowerCase()) return false;
  if (filters.protocol && protocol !== String(filters.protocol).toUpperCase()) return false;
  if (filters.destinationPort && destinationPort !== String(filters.destinationPort)) return false;
  if (filters.search && !searchTarget.includes(String(filters.search).toLowerCase())) return false;

  return true;
};

const Logs = () => {
  const [logList, setLogList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tableLoading, setTableLoading] = useState(false);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const [collectorHeartbeat, setCollectorHeartbeat] = useState(null);
  const [filters, setFilters] = useState({
    level: "",
    source: "",
    protocol: "",
    destinationPort: "",
    search: "",
  });

  const limit = 20;
  const token = localStorage.getItem("accessToken");
  const abortRef = useRef(null);
  const refreshTimerRef = useRef(null);
  const isMountedRef = useRef(true);
  const logListRef = useRef([]);

  useEffect(() => {
    logListRef.current = logList;
  }, [logList]);

  const fetchLogs = useCallback(async () => {
    try {
      setTableLoading(true);
      setError("");

      if (abortRef.current) abortRef.current.abort();
      abortRef.current = new AbortController();

      const requestFilters = Object.fromEntries(
        Object.entries(filters).filter(([, value]) => String(value || "").trim() !== "")
      );

      const res = await logs.list(limit, page, requestFilters);
      const data = res?.data?.data ?? [];
      const pagination = res?.data?.pagination ?? {};

      if (!isMountedRef.current) return;

      setLogList(data);
      setTotal(pagination.total ?? data.length);
    } catch (err) {
      console.error("Logs fetch error:", err);
      if (isMountedRef.current) {
        setError(err?.response?.data?.message || "Failed to fetch logs.");
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
        setTableLoading(false);
      }
    }
  }, [filters, page]);

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(fetchLogs, 300);
  }, [fetchLogs]);

  const hasActiveFilters = useMemo(
    () => Object.values(filters).some((value) => String(value || "").trim() !== ""),
    [filters]
  );

  const mergeIncomingLog = useCallback(
    (incoming) => {
      if (!incoming?._id) {
        scheduleRefresh();
        return;
      }

      if (!matchesFilters(incoming, filters)) return;

      const exists = logListRef.current.some((item) => item._id === incoming._id);

      setLogList((current) => {
        const updated = current.map((item) =>
          item._id === incoming._id ? { ...item, ...incoming } : item
        );

        if (exists) return updated;

        return [incoming, ...updated].slice(0, limit);
      });

      if (!exists) {
        setTotal((current) => current + 1);
      }
    },
    [filters, limit, scheduleRefresh]
  );

  const socketState = useSocket(
    token,
    useMemo(
      () => ({
        "logs:new": (payload) => {
          const incoming = resolveSocketLog(payload);

          if (page !== 1 || hasActiveFilters) {
            scheduleRefresh();
            return;
          }

          mergeIncomingLog(incoming);
        },
        "log:new": (payload) => {
          const incoming = resolveSocketLog(payload);

          if (page !== 1 || hasActiveFilters) {
            scheduleRefresh();
            return;
          }

          mergeIncomingLog(incoming);
        },
        "collector:heartbeat": (payload) => {
          setCollectorHeartbeat(payload?.data || payload || null);
        },
      }),
      [hasActiveFilters, mergeIncomingLog, page, scheduleRefresh]
    )
  );

  useEffect(() => {
    isMountedRef.current = true;
    fetchLogs();

    return () => {
      isMountedRef.current = false;
      clearTimeout(refreshTimerRef.current);
      if (abortRef.current) abortRef.current.abort();
    };
  }, [fetchLogs]);

  const trafficSummary = useMemo(() => {
    const totals = logList.reduce(
      (acc, log) => {
        const priority = priorityClass(getPriority(log));

        if (priority === "critical") acc.critical += 1;
        if (priority === "high") acc.high += 1;

        const srcIp = getSourceIp(log);
        const dstIp = getDestinationIp(log);

        if (srcIp !== "-") acc.sourceIps.add(srcIp);
        if (dstIp !== "-") acc.destinationIps.add(dstIp);

        acc.sources.add(String(getSourceName(log)));
        acc.protocols.add(String(getProtocol(log)).toUpperCase());

        return acc;
      },
      {
        critical: 0,
        high: 0,
        sourceIps: new Set(),
        destinationIps: new Set(),
        sources: new Set(),
        protocols: new Set(),
      }
    );

    return {
      critical: totals.critical,
      high: totals.high,
      uniqueSources: totals.sourceIps.size,
      uniqueDestinations: totals.destinationIps.size,
      telemetrySources: totals.sources.size,
      protocols: totals.protocols.size,
    };
  }, [logList]);

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const clearFilters = () => {
    setPage(1);
    setFilters({
      level: "",
      source: "",
      protocol: "",
      destinationPort: "",
      search: "",
    });
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading ThreatLens logs...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="tl-logs-page">
        <section className="tl-logs-header">
          <div>
            <h1>📜 ThreatLens Logs</h1>
            <p>
              Real-time hybrid telemetry from HIDS agents, NIDS collectors, Snort,
              backend services, rule engine, and ML detection pipeline.
            </p>
          </div>

          <button className="tl-logs-refresh" type="button" onClick={fetchLogs}>
            Refresh Logs
          </button>
        </section>

        {error && <div className="error-message">{error}</div>}

        <section className="tl-logs-status-grid">
          <div>
            <span>Socket Status</span>
            <strong className={`tl-live-status ${socketState.connectionStatus}`}>
              {socketState.connectionStatus}
            </strong>
            <small>{socketState.lastError || "Live event channel"}</small>
          </div>

          <div>
            <span>Collector</span>
            <strong>{collectorHeartbeat?.status || "unknown"}</strong>
            <small>{collectorHeartbeat?.agentType || "Waiting for heartbeat"}</small>
          </div>

          <div>
            <span>Last Heartbeat</span>
            <strong>{formatTimestamp(collectorHeartbeat?.receivedAt)}</strong>
            <small>{collectorHeartbeat?.hostname || "No collector signal yet"}</small>
          </div>
        </section>

        <section className="tl-logs-summary-grid">
          <div>
            <span>Visible Events</span>
            <strong>{logList.length}</strong>
          </div>
          <div>
            <span>Critical Priority</span>
            <strong>{trafficSummary.critical}</strong>
          </div>
          <div>
            <span>High Priority</span>
            <strong>{trafficSummary.high}</strong>
          </div>
          <div>
            <span>Unique Sources</span>
            <strong>{trafficSummary.uniqueSources}</strong>
          </div>
          <div>
            <span>Unique Destinations</span>
            <strong>{trafficSummary.uniqueDestinations}</strong>
          </div>
          <div>
            <span>Protocols</span>
            <strong>{trafficSummary.protocols}</strong>
          </div>
        </section>

        <section className="tl-logs-filter-panel">
          <div className="tl-logs-panel-title">Filter and Search</div>

          <div className="tl-logs-filter-body">
            <div className="tl-form-group">
              <label>Search Logs</label>
              <input
                type="text"
                placeholder="Search message, IP, protocol, event type"
                value={filters.search}
                onChange={(event) => {
                  setPage(1);
                  setFilters((prev) => ({ ...prev, search: event.target.value }));
                }}
              />
            </div>

            <div className="tl-form-group">
              <label>Level</label>
              <select
                value={filters.level}
                onChange={(event) => {
                  setPage(1);
                  setFilters((prev) => ({ ...prev, level: event.target.value }));
                }}
              >
                <option value="">All levels</option>
                <option value="info">Info</option>
                <option value="warn">Warn</option>
                <option value="error">Error</option>
              </select>
            </div>

            <div className="tl-form-group">
              <label>Source</label>
              <select
                value={filters.source}
                onChange={(event) => {
                  setPage(1);
                  setFilters((prev) => ({ ...prev, source: event.target.value }));
                }}
              >
                <option value="">All sources</option>
                <option value="host">Host telemetry</option>
                <option value="agent">Agent</option>
                <option value="snort">Snort</option>
                <option value="suricata">Suricata</option>
                <option value="ids-engine">IDS engine</option>
                <option value="ids-engine-ml">ML anomalies</option>
                <option value="rule-engine">Rule engine</option>
                <option value="backend">Backend requests</option>
                <option value="upload">Uploaded logs</option>
              </select>
            </div>

            <div className="tl-form-group">
              <label>Protocol</label>
              <select
                value={filters.protocol}
                onChange={(event) => {
                  setPage(1);
                  setFilters((prev) => ({ ...prev, protocol: event.target.value }));
                }}
              >
                <option value="">All protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="HTTP">HTTP</option>
                <option value="HTTPS">HTTPS</option>
                <option value="SSH">SSH</option>
                <option value="ICMP">ICMP</option>
                <option value="DNS">DNS</option>
              </select>
            </div>

            <div className="tl-form-group">
              <label>Destination Port</label>
              <input
                type="text"
                placeholder="22, 80, 443"
                value={filters.destinationPort}
                onChange={(event) => {
                  setPage(1);
                  setFilters((prev) => ({ ...prev, destinationPort: event.target.value }));
                }}
              />
            </div>

            <button className="tl-clear-logs-btn" type="button" onClick={clearFilters}>
              Clear
            </button>
          </div>
        </section>

        <section className="tl-logs-table-card">
          <div className="tl-logs-table-title">
            <h3>▦ Live Event Stream</h3>
            <span>{total} logs found</span>
          </div>

          {tableLoading ? (
            <div className="tl-logs-empty">Refreshing logs...</div>
          ) : logList.length > 0 ? (
            <>
              <div className="tl-logs-table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Message</th>
                      <th>Classification</th>
                      <th>Priority</th>
                      <th>Protocol</th>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Dest Port</th>
                      <th>Source</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>

                  <tbody>
                    {logList.map((log) => {
                      const priority = getPriority(log);
                      const priorityTone = priorityClass(priority);

                      return (
                        <tr key={log._id || `${log.timestamp}-${log.message}`}>
                          <td className="tl-log-message">
                            {log.message || log.eventType || "-"}
                          </td>
                          <td>{getClassification(log)}</td>
                          <td>
                            <span className={`tl-log-priority ${priorityTone}`}>
                              {priority}
                            </span>
                          </td>
                          <td>
                            <span className="tl-protocol-pill">{getProtocol(log)}</span>
                          </td>
                          <td className="tl-log-ip">{getSourceIp(log)}</td>
                          <td className="tl-log-ip">{getDestinationIp(log)}</td>
                          <td className="tl-log-port">{getDestinationPort(log)}</td>
                          <td>{getSourceName(log)}</td>
                          <td>{formatTimestamp(log.timestamp || log.createdAt)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="tl-logs-pagination">
                <button
                  type="button"
                  onClick={() => setPage((current) => Math.max(current - 1, 1))}
                  disabled={page === 1}
                >
                  Previous
                </button>

                <span>
                  Page {page} of {totalPages}
                </span>

                <button
                  type="button"
                  onClick={() => setPage((current) => Math.min(current + 1, totalPages))}
                  disabled={page >= totalPages}
                >
                  Next
                </button>
              </div>
            </>
          ) : (
            <div className="tl-logs-empty">
              No telemetry is available yet. Keep your HIDS agent, Snort collector,
              or upload pipeline running to populate this stream.
            </div>
          )}
        </section>
      </div>
    </MainLayout>
  );
};

export default Logs;