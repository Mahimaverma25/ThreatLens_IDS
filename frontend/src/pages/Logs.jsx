import { useCallback, useEffect, useMemo, useState } from "react";
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

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true);
      const res = await logs.list(limit, page, filters);
      setLogList(res.data.data);
      setTotal(res.data.pagination.total);
    } catch (err) {
      setError("Failed to fetch logs");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  const socketHandlers = useMemo(
    () => ({
      "logs:new": () => fetchLogs(),
    }),
    [fetchLogs]
  );

  useSocket(token, socketHandlers);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const handleUpload = async () => {
    if (!uploadFile) return;
    try {
      await logs.upload(uploadFile);
      setUploadFile(null);
      fetchLogs();
    } catch (err) {
      setError("Failed to upload logs");
    }
  };

  const handleSimulate = async () => {
    try {
      await logs.simulate(simulateCount);
      fetchLogs();
    } catch (err) {
      setError("Failed to simulate traffic");
    }
  };

  if (loading) return <MainLayout><div className="loading">Loading...</div></MainLayout>;

  const totalPages = Math.ceil(total / limit);

  return (
    <MainLayout>
      <h1>Event Logs</h1>
      <p>Network traffic logs and system events are stored here for monitoring and analysis.</p>

      {error && <div className="error-message">{error}</div>}

      <div className="controls">
        <input
          className="search-input"
          placeholder="Search message or event"
          value={filters.search}
          onChange={(e) => {
            setPage(1);
            setFilters({ ...filters, search: e.target.value });
          }}
        />
        <select
          value={filters.level}
          onChange={(e) => {
            setPage(1);
            setFilters({ ...filters, level: e.target.value });
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
            setFilters({ ...filters, source: e.target.value });
          }}
        >
          <option value="">All sources</option>
          <option value="request">Request</option>
          <option value="auth">Auth</option>
          <option value="ids-engine">IDS</option>
          <option value="simulator">Simulator</option>
        </select>
      </div>

      <div className="card">
        <h3>Ingestion Tools</h3>
        <div className="action-row">
          <input
            type="file"
            accept=".json,.csv"
            onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
          />
          <button className="scan-btn" onClick={handleUpload} disabled={!uploadFile}>
            Upload Logs
          </button>
          <input
            className="note-input"
            type="number"
            min="1"
            max="200"
            value={simulateCount}
            onChange={(e) => setSimulateCount(Number(e.target.value))}
          />
          <button className="scan-btn" onClick={handleSimulate}>
            Simulate Traffic
          </button>
        </div>
      </div>

      <div className="card">
        {logList.length > 0 ? (
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
                {logList.map((log, idx) => (
                  <tr key={idx}>
                    <td className="message-cell">{log.message}</td>
                    <td>
                      <span className={`level level-${log.level?.toLowerCase()}`}>
                        {log.level}
                      </span>
                    </td>
                    <td>{log.source}</td>
                    <td className="ip-cell">{log.ip || "-"}</td>
                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <button
                onClick={() => setPage(Math.max(page - 1, 1))}
                disabled={page === 1}
              >
                ← Previous
              </button>
              <span>
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage(Math.min(page + 1, totalPages))}
                disabled={page === totalPages}
              >
                Next →
              </button>
            </div>
          </>
        ) : (
          <p>No logs available yet.</p>
        )}
      </div>

      <button onClick={fetchLogs} className="refresh-btn">
        🔄 Refresh
      </button>
    </MainLayout>
  );
};

export default Logs;
