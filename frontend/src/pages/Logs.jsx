import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { logs } from "../services/api";
import useSocket from "../hooks/useSocket";

const Logs = () => {
  const [logList, setLogList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState({
    level: "",
    source: "snort",
    protocol: "",
    destinationPort: "",
    search: ""
  });

  const limit = 20;
  const token = localStorage.getItem("accessToken");
  const abortRef = useRef(null);
  const isMountedRef = useRef(true);
  const refreshTimerRef = useRef(null);

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

  const socketHandlers = useMemo(
    () => ({
      "logs:new": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchLogs, 300);
      }
    }),
    [fetchLogs]
  );

  useSocket(token, socketHandlers);

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
        if ((log.metadata?.snort?.priority || 0) <= 1) {
          accumulator.critical += 1;
        }

        if ((log.metadata?.snort?.priority || 0) === 2) {
          accumulator.high += 1;
        }

        if (log.metadata?.snort?.srcIp || log.ip) {
          accumulator.sourceIps.add(log.metadata?.snort?.srcIp || log.ip);
        }

        if (log.metadata?.snort?.destIp) {
          accumulator.destinationIps.add(log.metadata.snort.destIp);
        }

        return accumulator;
      },
      { critical: 0, high: 0, sourceIps: new Set(), destinationIps: new Set() }
    );

    return {
      critical: totals.critical,
      high: totals.high,
      uniqueSources: totals.sourceIps.size,
      uniqueDestinations: totals.destinationIps.size
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
          <div className="command-eyebrow">Network / ThreatLens / Telemetry</div>
          <h1>Live Snort Event Stream</h1>
          <p>
            Review real Snort alerts as they arrive through the agent, including signatures,
            classifications, priorities, source IPs, destination IPs, and protocols.
          </p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

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
      </section>

      <div className="controls">
        <input
          className="search-input"
          placeholder="Search message, protocol, or event"
          value={filters.search}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({ ...prev, search: e.target.value }));
          }}
        />

        <select
          value={filters.level}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({ ...prev, level: e.target.value }));
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
            setFilters((prev) => ({ ...prev, source: e.target.value }));
          }}
        >
          <option value="snort">Live Snort</option>
          <option value="">All real sources</option>
          <option value="request">Backend Requests</option>
          <option value="upload">Uploaded Logs</option>
        </select>

        <select
          value={filters.protocol}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({ ...prev, protocol: e.target.value }));
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
            setFilters((prev) => ({ ...prev, destinationPort: e.target.value }));
          }}
        />
      </div>

      <div className="card">
        {logList?.length > 0 ? (
          <>
            <table>
              <thead>
                <tr>
                  <th>Signature</th>
                  <th>Classification</th>
                  <th>Priority</th>
                  <th>Protocol</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Dest Port</th>
                  <th>Timestamp</th>
                </tr>
              </thead>

              <tbody>
                {logList.map((log) => (
                  <tr key={log._id}>
                    <td className="message-cell">{log.message}</td>
                    <td>{log.metadata?.snort?.classification || "-"}</td>
                    <td>{log.metadata?.snort?.priority || "-"}</td>
                    <td>{log.metadata?.protocol || "-"}</td>
                    <td className="ip-cell">{log.metadata?.snort?.srcIp || log.ip || "-"}</td>
                    <td className="ip-cell">{log.metadata?.snort?.destIp || "-"}</td>
                    <td className="mono-text">
                      {log.metadata?.destinationPort || log.metadata?.port || "-"}
                    </td>
                    <td>
                      {log.timestamp ? new Date(log.timestamp).toLocaleString() : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <button
                onClick={() => setPage((p) => Math.max(p - 1, 1))}
                disabled={page === 1}
              >
                Previous
              </button>

              <span>
                Page {page} of {totalPages}
              </span>

              <button
                onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
                disabled={page >= totalPages}
              >
                Next
              </button>
            </div>
          </>
        ) : (
          <p>
            No Snort logs available yet. Keep the ThreatLens agent running and generate or ingest a
            Snort alert to populate this table.
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
