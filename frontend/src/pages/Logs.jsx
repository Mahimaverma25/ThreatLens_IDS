import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { logs } from "../services/api";
import useSocket from "../hooks/useSocket";
import { useAuth } from "../context/AuthContext";

const formatBytes = (value) => {
  const bytes = Number(value || 0);

  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
};

const Logs = () => {
  const { user } = useAuth();
  const [logList, setLogList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState({
    level: "",
    source: "",
    protocol: "",
    destinationPort: "",
    search: ""
  });
  const [uploadFile, setUploadFile] = useState(null);
  const [simulateCount, setSimulateCount] = useState(10);

  const limit = 20;
  const isAdmin = user?.role === "admin";
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

  const handleUpload = async () => {
    if (!uploadFile) return;

    try {
      setError("");
      await logs.upload(uploadFile);
      setUploadFile(null);
      fetchLogs();
    } catch (err) {
      console.error("Upload error:", err);
      setError("Failed to upload logs");
    }
  };

  const handleSimulate = async () => {
    try {
      setError("");
      await logs.simulate(simulateCount);
      fetchLogs();
    } catch (err) {
      console.error("Simulate error:", err);
      setError("Failed to simulate traffic");
    }
  };

  const trafficSummary = useMemo(() => {
    const totals = logList.reduce(
      (accumulator, log) => {
        accumulator.bytes += Number(log.metadata?.bytes || 0);
        accumulator.failedAttempts += Number(log.metadata?.failedAttempts || 0);
        accumulator.avgRate += Number(log.metadata?.requestRate || 0);
        return accumulator;
      },
      { bytes: 0, failedAttempts: 0, avgRate: 0 }
    );

    return {
      bytes: totals.bytes,
      failedAttempts: totals.failedAttempts,
      avgRate: logList.length ? Math.round(totals.avgRate / logList.length) : 0
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
          <h1>Network Event Logs</h1>
          <p>
            Review network flows with protocol, bytes, duration, failed attempts,
            destination ports, and request-rate telemetry.
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
          <span>Total Bytes</span>
          <strong>{formatBytes(trafficSummary.bytes)}</strong>
        </div>
        <div className="metric-card">
          <span>Failed Attempts</span>
          <strong>{trafficSummary.failedAttempts}</strong>
        </div>
        <div className="metric-card">
          <span>Avg Request Rate</span>
          <strong>{trafficSummary.avgRate}/min</strong>
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
          <option value="">All sources</option>
          <option value="request">Request</option>
          <option value="auth">Auth</option>
          <option value="ids-engine">IDS</option>
          <option value="simulator">Simulator</option>
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
        <h3>Ingestion Tools</h3>
        {!isAdmin && <p>Viewer access is read-only. Upload and simulation actions are disabled.</p>}

        <div className="action-row">
          <input
            type="file"
            accept=".json,.csv"
            disabled={!isAdmin}
            onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
          />

          <button className="scan-btn" onClick={handleUpload} disabled={!isAdmin || !uploadFile}>
            Upload Logs
          </button>

          <input
            className="note-input"
            type="number"
            min="1"
            max="200"
            value={simulateCount}
            disabled={!isAdmin}
            onChange={(e) => setSimulateCount(Number(e.target.value))}
          />

          <button className="scan-btn" onClick={handleSimulate} disabled={!isAdmin}>
            Simulate Traffic
          </button>
        </div>
      </div>

      <div className="card">
        {logList?.length > 0 ? (
          <>
            <table>
              <thead>
                <tr>
                  <th>Message</th>
                  <th>Protocol</th>
                  <th>Bytes</th>
                  <th>Duration</th>
                  <th>Flags</th>
                  <th>Dest Port</th>
                  <th>Req Rate</th>
                  <th>Flow Count</th>
                  <th>IP</th>
                  <th>Timestamp</th>
                </tr>
              </thead>

              <tbody>
                {logList.map((log) => (
                  <tr key={log._id}>
                    <td className="message-cell">{log.message}</td>
                    <td>{log.metadata?.protocol || "-"}</td>
                    <td>{formatBytes(log.metadata?.bytes)}</td>
                    <td>{log.metadata?.duration ? `${log.metadata.duration}s` : "-"}</td>
                    <td>{Array.isArray(log.metadata?.flags) ? log.metadata.flags.join(", ") : "-"}</td>
                    <td className="mono-text">
                      {log.metadata?.destinationPort || log.metadata?.port || "-"}
                    </td>
                    <td>{log.metadata?.requestRate || "-"}</td>
                    <td>{log.metadata?.flowCount || "-"}</td>
                    <td className="ip-cell">{log.ip || "-"}</td>
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
          <p>No logs available yet.</p>
        )}
      </div>

      <button onClick={fetchLogs} className="refresh-btn">
        Refresh Logs
      </button>
    </MainLayout>
  );
};

export default Logs;
