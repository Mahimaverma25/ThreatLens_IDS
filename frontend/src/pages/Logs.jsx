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
  log?.ip ||
  "-";

const getDestinationIp = (log) =>
  log?.metadata?.snort?.destIp ||
  log?.metadata?.destinationIp ||
  "-";

const getDestinationPort = (log) =>
  log?.metadata?.destinationPort ||
  log?.metadata?.port ||
  log?.metadata?.snort?.destPort ||
  "-";

const matchesFilters = (log, filters) => {
  const protocol = String(getProtocol(log)).toUpperCase();
  const destinationPort = String(getDestinationPort(log));
  const source = String(log?.metadata?.sensorType || log?.source || "").toLowerCase();
  const searchTarget = [
    log?.message,
    log?.eventType,
    getClassification(log),
    protocol,
    source,
    getSourceIp(log),
    getDestinationIp(log),
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
  const isMountedRef = useRef(true);
  const refreshTimerRef = useRef(null);
  const logListRef = useRef([]);

  useEffect(() => {
    logListRef.current = logList;
  }, [logList]);

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      if (abortRef.current) {
        abortRef.current.abort();
      }

      abortRef.current = new AbortController();

      const requestFilters = Object.fromEntries(
        Object.entries(filters).filter(([, value]) => value !== "")
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
        setError("Failed to fetch logs");
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [page, filters]);

  const scheduleRefresh = useCallback(() => {
    clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(fetchLogs, 300);
  }, [fetchLogs]);

  const hasActiveFilters = useMemo(
    () => Object.values(filters).some((value) => String(value || "").trim() !== ""),
    [filters]
  );

  const mergeIncomingLog = useCallback((incoming) => {
    if (!incoming?._id) {
      scheduleRefresh();
      return;
    }

    if (!matchesFilters(incoming, filters)) {
      return;
    }

    const exists = logListRef.current.some((item) => item._id === incoming._id);

    setLogList((current) => {
      const next = current.map((item) => (item._id === incoming._id ? { ...item, ...incoming } : item));
      if (exists) {
        return next;
      }
      return [incoming, ...next].slice(0, limit);
    });

    if (!exists) {
      setTotal((current) => current + 1);
    }
  }, [filters, limit, scheduleRefresh]);

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
      if (abortRef.current) {
        abortRef.current.abort();
      }
    };
  }, [fetchLogs]);

  const trafficSummary = useMemo(() => {
    const totals = logList.reduce(
      (accumulator, log) => {
        const priority = Number(getPriority(log));
        if (!Number.isNaN(priority) && priority <= 1) {
          accumulator.critical += 1;
        }

        if (!Number.isNaN(priority) && priority === 2) {
          accumulator.high += 1;
        }

        if (getSourceIp(log) !== "-") {
          accumulator.sourceIps.add(getSourceIp(log));
        }

        if (getDestinationIp(log) !== "-") {
          accumulator.destinationIps.add(getDestinationIp(log));
        }

        accumulator.sources.add(String(log?.metadata?.sensorType || log?.source || "unknown"));
        return accumulator;
      },
      { critical: 0, high: 0, sourceIps: new Set(), destinationIps: new Set(), sources: new Set() }
    );

    return {
      critical: totals.critical,
      high: totals.high,
      uniqueSources: totals.sourceIps.size,
      uniqueDestinations: totals.destinationIps.size,
      telemetrySources: totals.sources.size,
    };
  }, [logList]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading logs...</div>
      </MainLayout>
    );
  }

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">Hybrid telemetry / ThreatLens / live event stream</div>
          <h1>Hybrid Event Stream</h1>
          <p>
            Review host, network, rule-engine, and ML-enriched telemetry as it arrives through the ThreatLens pipeline.
          </p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Socket</span>
          <strong>{socketState.connectionStatus}</strong>
          <small>{socketState.lastError || "Live event channel"}</small>
        </div>
        <div className="metric-card">
          <span>Collector</span>
          <strong>{collectorHeartbeat?.status || "unknown"}</strong>
          <small>{collectorHeartbeat?.agentType || "Waiting for heartbeat"}</small>
        </div>
        <div className="metric-card">
          <span>Last Heartbeat</span>
          <strong>{formatTimestamp(collectorHeartbeat?.receivedAt)}</strong>
          <small>{collectorHeartbeat?.hostname || "No collector signal yet"}</small>
        </div>
      </section>

      <section className="metrics-grid">
        <div className="metric-card">
          <span>Visible Events</span>
          <strong>{logList.length}</strong>
        </div>
        <div className="metric-card">
          <span>Critical Priority</span>
          <strong>{trafficSummary.critical}</strong>
        </div>
        <div className="metric-card">
          <span>High Priority</span>
          <strong>{trafficSummary.high}</strong>
        </div>
        <div className="metric-card">
          <span>Unique Sources</span>
          <strong>{trafficSummary.uniqueSources}</strong>
        </div>
        <div className="metric-card">
          <span>Unique Destinations</span>
          <strong>{trafficSummary.uniqueDestinations}</strong>
        </div>
        <div className="metric-card">
          <span>Telemetry Sources</span>
          <strong>{trafficSummary.telemetrySources}</strong>
        </div>
      </section>

      <div className="controls">
        <input
          className="search-input"
          placeholder="Search message, source, IP, or event type"
          value={filters.search}
          onChange={(e) => {
            setPage(1);
            setFilters((previous) => ({ ...previous, search: e.target.value }));
          }}
        />

        <select
          value={filters.level}
          onChange={(e) => {
            setPage(1);
            setFilters((previous) => ({ ...previous, level: e.target.value }));
          }}
        >
          <option value="">All levels</option>
          <option value="info">Info</option>
          <option value="warn">Warn</option>
          <option value="error">Error</option>
        </select>

        <select
          value={filters.source}
          onChange={(e) => {
            setPage(1);
            setFilters((previous) => ({ ...previous, source: e.target.value }));
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

        <select
          value={filters.protocol}
          onChange={(e) => {
            setPage(1);
            setFilters((previous) => ({ ...previous, protocol: e.target.value }));
          }}
        >
          <option value="">All protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="HTTP">HTTP</option>
          <option value="HTTPS">HTTPS</option>
          <option value="SSH">SSH</option>
        </select>

        <input
          className="note-input"
          placeholder="Dest port"
          value={filters.destinationPort}
          onChange={(e) => {
            setPage(1);
            setFilters((previous) => ({ ...previous, destinationPort: e.target.value }));
          }}
        />
      </div>

      <div className="card">
        {logList?.length > 0 ? (
          <>
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
                {logList.map((log) => (
                  <tr key={log._id}>
                    <td className="message-cell">{log.message || log.eventType || "-"}</td>
                    <td>{getClassification(log)}</td>
                    <td>{getPriority(log)}</td>
                    <td>{getProtocol(log)}</td>
                    <td className="ip-cell">{getSourceIp(log)}</td>
                    <td className="ip-cell">{getDestinationIp(log)}</td>
                    <td className="mono-text">{getDestinationPort(log)}</td>
                    <td>{log?.metadata?.sensorType || log?.source || "-"}</td>
                    <td>{log.timestamp ? new Date(log.timestamp).toLocaleString() : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <button onClick={() => setPage((current) => Math.max(current - 1, 1))} disabled={page === 1}>
                Previous
              </button>

              <span>
                Page {page} of {totalPages}
              </span>

              <button
                onClick={() => setPage((current) => Math.min(current + 1, totalPages))}
                disabled={page >= totalPages}
              >
                Next
              </button>
            </div>
          </>
        ) : (
          <p>
            No telemetry is available yet. Keep the host agent, Snort collector, or log ingest pipeline running to populate this stream.
          </p>
        )}
      </div>

      <button onClick={fetchLogs} className="refresh-btn">
        Refresh Logs
      </button>
    </MainLayout>
  );
};

export default Logs;
