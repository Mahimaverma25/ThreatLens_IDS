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
    source: "",
    search: "",
  });

  const [uploadFile, setUploadFile] = useState(null);
  const [simulateCount, setSimulateCount] = useState(10);

  const limit = 20;
  const token = localStorage.getItem("accessToken");

  const abortRef = useRef(null);
  const isMountedRef = useRef(true);
  const refreshTimerRef = useRef(null);

  /* ================= FETCH LOGS ================= */

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      if (abortRef.current) {
        abortRef.current.abort();
      }

      abortRef.current = new AbortController();

      const res = await logs.list(limit, page, filters);

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

  /* ================= SOCKET ================= */

  const socketHandlers = useMemo(
    () => ({
      "logs:new": () => {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(fetchLogs, 300);
      },
    }),
    [fetchLogs]
  );

  useSocket(token, socketHandlers);

  /* ================= INIT LOAD ================= */

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

  /* ================= UPLOAD LOGS ================= */

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

  /* ================= SIMULATE ================= */

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

  /* ================= LOADING ================= */

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading logs...</div>
      </MainLayout>
    );
  }

  const totalPages = Math.max(1, Math.ceil(total / limit));

  /* ================= UI ================= */

  return (
    <MainLayout>
      <h1>Event Logs</h1>
      <p>
        Network traffic logs and system events are stored here for monitoring
        and analysis.
      </p>

      {error && <div className="error-message">{error}</div>}

      {/* ================= FILTERS ================= */}

      <div className="controls">
        <input
          className="search-input"
          placeholder="Search message or event"
          value={filters.search}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({
              ...prev,
              search: e.target.value,
            }));
          }}
        />

        <select
          value={filters.level}
          onChange={(e) => {
            setPage(1);
            setFilters((prev) => ({
              ...prev,
              level: e.target.value,
            }));
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
            setFilters((prev) => ({
              ...prev,
              source: e.target.value,
            }));
          }}
        >
          <option value="">All sources</option>
          <option value="request">Request</option>
          <option value="auth">Auth</option>
          <option value="ids-engine">IDS</option>
          <option value="simulator">Simulator</option>
        </select>
      </div>

      {/* ================= INGESTION ================= */}

      <div className="card">
        <h3>Ingestion Tools</h3>

        <div className="action-row">
          <input
            type="file"
            accept=".json,.csv"
            onChange={(e) =>
              setUploadFile(e.target.files?.[0] || null)
            }
          />

          <button
            className="scan-btn"
            onClick={handleUpload}
            disabled={!uploadFile}
          >
            Upload Logs
          </button>

          <input
            className="note-input"
            type="number"
            min="1"
            max="200"
            value={simulateCount}
            onChange={(e) =>
              setSimulateCount(Number(e.target.value))
            }
          />

          <button className="scan-btn" onClick={handleSimulate}>
            Simulate Traffic
          </button>
        </div>
      </div>

      {/* ================= LOG TABLE ================= */}

      <div className="card">
        {logList?.length > 0 ? (
          <>
            <table>
              <thead>
                <tr>
                  <th>Message</th>
                  <th>Level</th>
                  <th>Source</th>
                  <th>IP</th>
                  <th>Timestamp</th>
                </tr>
              </thead>

              <tbody>
                {logList.map((log) => (
                  <tr key={log._id}>
                    <td className="message-cell">{log.message}</td>

                    <td>
                      <span
                        className={`level level-${log.level?.toLowerCase()}`}
                      >
                        {log.level}
                      </span>
                    </td>

                    <td>{log.source}</td>

                    <td className="ip-cell">{log.ip || "-"}</td>

                    <td>
                      {log.timestamp
                        ? new Date(log.timestamp).toLocaleString()
                        : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* ================= PAGINATION ================= */}

            <div className="pagination">
              <button
                onClick={() => setPage((p) => Math.max(p - 1, 1))}
                disabled={page === 1}
              >
                ← Previous
              </button>

              <span>
                Page {page} of {totalPages}
              </span>

              <button
                onClick={() =>
                  setPage((p) => Math.min(p + 1, totalPages))
                }
                disabled={page >= totalPages}
              >
                Next →
              </button>
            </div>
          </>
        ) : (
          <p>No logs available yet.</p>
        )}
      </div>

      {/* ================= REFRESH ================= */}

      <button onClick={fetchLogs} className="refresh-btn">
        🔄 Refresh
      </button>
    </MainLayout>
  );
};

export default Logs;