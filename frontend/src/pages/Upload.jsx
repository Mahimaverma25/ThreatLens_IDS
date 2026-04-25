import { useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { uploads } from "../services/api";

const SAMPLE_CSV = [
  "message,source,eventType,protocol,sourceIp,destinationIp,destinationPort,severity,timestamp",
  '"Suspicious outbound connection","upload","network.alert","TCP","192.168.1.12","10.10.20.7",443,"high","2026-04-24T12:15:00.000Z"',
  '"Repeated authentication failure","upload","auth.failure","SSH","192.168.1.99","10.10.20.21",22,"medium","2026-04-24T12:18:00.000Z"',
].join("\n");

const EXPECTED_HEADERS = [
  "message",
  "source",
  "eventType",
  "protocol",
  "sourceIp",
  "destinationIp",
  "destinationPort",
  "severity",
  "timestamp",
];

const splitCsvLine = (line) => {
  const values = [];
  let current = "";
  let quoted = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];

    if (char === '"' && quoted && next === '"') {
      current += '"';
      i += 1;
      continue;
    }

    if (char === '"') {
      quoted = !quoted;
      continue;
    }

    if (char === "," && !quoted) {
      values.push(current.trim());
      current = "";
      continue;
    }

    current += char;
  }

  values.push(current.trim());
  return values;
};

const readCsvValidation = async (file) => {
  const content = await file.text();
  const lines = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (!lines.length) {
    return {
      validRows: 0,
      invalidRows: [{ rowNumber: 0, message: "CSV file is empty." }],
      detectedHeaders: [],
    };
  }

  const detectedHeaders = splitCsvLine(lines[0]);
  const invalidRows = [];
  let validRows = 0;

  const missingHeaders = EXPECTED_HEADERS.filter(
    (header) => !detectedHeaders.includes(header)
  );

  if (missingHeaders.length) {
    invalidRows.push({
      rowNumber: 1,
      message: `Missing required columns: ${missingHeaders.join(", ")}`,
    });
  }

  lines.slice(1).forEach((line, index) => {
    const values = splitCsvLine(line);
    const rowNumber = index + 2;

    if (values.length !== detectedHeaders.length) {
      invalidRows.push({
        rowNumber,
        message: "Column count does not match the header row.",
      });
      return;
    }

    const row = detectedHeaders.reduce((acc, header, headerIndex) => {
      acc[header] = values[headerIndex];
      return acc;
    }, {});

    if (!String(row.message || "").trim()) {
      invalidRows.push({
        rowNumber,
        message: "Message is required.",
      });
      return;
    }

    validRows += 1;
  });

  return { validRows, invalidRows, detectedHeaders };
};

const resolveUploadedRows = (payload) => {
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.predictions)) return payload.predictions;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.rows)) return payload.rows;
  return [];
};

const resolveInvalidRows = (payload) => {
  if (Array.isArray(payload?.invalidRows)) return payload.invalidRows;
  if (Array.isArray(payload?.errors)) return payload.errors;
  if (Array.isArray(payload?.meta?.invalidRows)) return payload.meta.invalidRows;
  return [];
};

const Upload = () => {
  const inputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [processingText, setProcessingText] = useState("");
  const [error, setError] = useState("");
  const [validation, setValidation] = useState({
    validRows: 0,
    invalidRows: [],
    detectedHeaders: [],
  });
  const [predictionType, setPredictionType] = useState("automatic");
  const [lotSize, setLotSize] = useState("500");
  const [result, setResult] = useState(null);

  const predictionRows = useMemo(() => resolveUploadedRows(result), [result]);
  const uploadErrors = useMemo(() => resolveInvalidRows(result), [result]);
  const hasUploadResult = Boolean(result);

  const handleSelectedFile = async (nextFile) => {
    if (!nextFile) return;

    if (!nextFile.name.toLowerCase().endsWith(".csv")) {
      setError("Only CSV files are supported.");
      return;
    }

    if (nextFile.size > 30 * 1024 * 1024) {
      setError("CSV file size must be less than 30 MB.");
      return;
    }

    setError("");
    setResult(null);
    setProgress(0);
    setProcessingText("");
    setFile(nextFile);

    try {
      const nextValidation = await readCsvValidation(nextFile);
      setValidation(nextValidation);
    } catch (err) {
      console.error("CSV validation error:", err);
      setValidation({ validRows: 0, invalidRows: [], detectedHeaders: [] });
      setError("The CSV file could not be read.");
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setError("Please select a CSV file first.");
      return;
    }

    try {
      setUploading(true);
      setError("");
      setResult(null);
      setProgress(20);
      setProcessingText("Loading and processing...");

      const timerOne = setTimeout(() => {
        setProgress(55);
        setProcessingText("Validating CSV traffic rows...");
      }, 350);

      const timerTwo = setTimeout(() => {
        setProgress(90);
        setProcessingText("Running IDS machine learning analysis...");
      }, 850);

      const response = await uploads.uploadCsv(file);

      clearTimeout(timerOne);
      clearTimeout(timerTwo);

      setProgress(100);
      setProcessingText("Analysis completed successfully.");
      setResult(response?.data ?? null);
    } catch (err) {
      console.error("CSV upload error:", err);
      setProgress(0);
      setProcessingText("");
      setError(err?.response?.data?.message || "Failed to analyze CSV.");
    } finally {
      setUploading(false);
    }
  };

  const downloadSample = () => {
    const blob = new Blob([SAMPLE_CSV], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = "ids-sample-upload.csv";
    anchor.click();

    URL.revokeObjectURL(url);
  };

  const clearUpload = () => {
    setFile(null);
    setResult(null);
    setError("");
    setProgress(0);
    setProcessingText("");
    setValidation({ validRows: 0, invalidRows: [], detectedHeaders: [] });

    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <MainLayout>
      <style>{`
        .upload-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background:
            radial-gradient(circle at top left, rgba(14, 165, 233, 0.1), transparent 30%),
            radial-gradient(circle at top right, rgba(249, 115, 22, 0.12), transparent 26%),
            linear-gradient(135deg, #07111f 0%, #0b1728 50%, #0a1422 100%);
        }

        .upload-shell {
          max-width: 1180px;
          margin: 0 auto;
        }

        .upload-topbar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 20px;
          margin-bottom: 26px;
        }

        .upload-title h1 {
          margin: 0;
          font-size: 32px;
          color: #f3f7ff;
          display: flex;
          align-items: center;
          gap: 12px;
          letter-spacing: -0.5px;
        }

        .upload-title p {
          margin: 8px 0 0;
          color: #9bb0cb;
          font-size: 15px;
        }

        .upload-top-actions {
          display: flex;
          align-items: center;
          gap: 14px;
          flex-wrap: wrap;
        }

        .link-action {
          border: 0;
          background: transparent;
          color: #8fe7ff;
          font-weight: 800;
          cursor: pointer;
          font-size: 14px;
        }

        .upload-layout {
          display: grid;
          grid-template-columns: minmax(0, 2fr) minmax(300px, 0.95fr);
          gap: 24px;
          align-items: start;
        }

        .upload-card {
          background: rgba(9, 18, 33, 0.92);
          border-radius: 18px;
          box-shadow: 0 18px 45px rgba(0, 0, 0, 0.24);
          border: 1px solid rgba(148, 163, 184, 0.12);
          overflow: hidden;
        }

        .upload-card-header {
          background: linear-gradient(90deg, #ff9b2f, #f07b1f);
          padding: 17px 22px;
          color: #08111f;
          font-size: 17px;
          font-weight: 900;
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .upload-card-body {
          padding: 26px;
        }

        .dropzone {
          min-height: 278px;
          border: 2px dashed rgba(93, 223, 255, 0.45);
          border-radius: 16px;
          background:
            radial-gradient(circle at top, rgba(93, 223, 255, 0.12), transparent 35%),
            linear-gradient(135deg, rgba(12, 24, 42, 0.96), rgba(9, 19, 35, 0.96));
          display: flex;
          align-items: center;
          justify-content: center;
          text-align: center;
          cursor: pointer;
          transition: 0.25s ease;
          padding: 28px;
        }

        .dropzone:hover,
        .dropzone.active {
          transform: translateY(-2px);
          border-color: #5ddfff;
          box-shadow: inset 0 0 0 999px rgba(93, 223, 255, 0.04);
        }

        .dropzone-icon {
          font-size: 46px;
          margin-bottom: 10px;
          color: #5ddfff;
          font-weight: 900;
          letter-spacing: 0.08em;
        }

        .dropzone h2 {
          margin: 0;
          color: #f3f7ff;
          font-size: 22px;
          font-weight: 900;
        }

        .dropzone p {
          margin: 8px 0 16px;
          color: #9bb0cb;
        }

        .dropzone-badges {
          display: flex;
          justify-content: center;
          gap: 8px;
          flex-wrap: wrap;
        }

        .dropzone-badges span {
          background: rgba(21, 40, 66, 0.92);
          color: #dcecff;
          padding: 7px 13px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 900;
          border: 1px solid rgba(148, 163, 184, 0.12);
          box-shadow: 0 8px 16px rgba(0, 0, 0, 0.18);
        }

        .hidden-input {
          display: none;
        }

        .selected-file-card {
          margin-top: 16px;
          background:
            radial-gradient(circle at top right, rgba(255, 155, 47, 0.12), transparent 34%),
            radial-gradient(circle at bottom left, rgba(93, 223, 255, 0.12), transparent 32%),
            linear-gradient(135deg, rgba(10, 20, 36, 0.96), rgba(13, 27, 48, 0.94));
          border-radius: 14px;
          padding: 16px 18px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          border: 1px solid rgba(93, 223, 255, 0.18);
          box-shadow: 0 12px 28px rgba(2, 6, 18, 0.24);
        }

        .selected-file-card strong {
          display: block;
          color: #f8fbff;
          font-size: 15px;
          margin-bottom: 5px;
        }

        .selected-file-card span {
          color: #9fb4d2;
          font-size: 13px;
        }

        .clear-link {
          border: 0;
          background: transparent;
          color: #ffbe78;
          cursor: pointer;
          font-weight: 900;
          white-space: nowrap;
        }

        .clear-link:hover {
          color: #ffd166;
        }

        .progress-wrap {
          margin-top: 14px;
        }

        .progress-track {
          height: 16px;
          border-radius: 999px;
          background: rgba(20, 36, 60, 0.92);
          overflow: hidden;
        }

        .progress-fill {
          height: 100%;
          background: linear-gradient(90deg, #5ddfff, #2f7df6);
          color: #08111f;
          font-size: 11px;
          font-weight: 900;
          text-align: center;
          line-height: 16px;
          transition: width 0.35s ease;
        }

        .progress-wrap p {
          margin: 9px 0 0;
          color: #9bb0cb;
          font-size: 13px;
        }

        .upload-controls {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 18px;
          margin-top: 20px;
        }

        .control-group label {
          display: block;
          margin-bottom: 8px;
          font-weight: 900;
          color: #dcecff;
          font-size: 14px;
        }

        .control-group select {
          width: 100%;
          height: 46px;
          border-radius: 10px;
          border: 1px solid rgba(148, 163, 184, 0.18);
          padding: 0 14px;
          color: #dcecff;
          background: rgba(7, 15, 29, 0.9);
          outline: none;
        }

        .primary-action {
          width: 100%;
          margin-top: 22px;
          border: 0;
          border-radius: 12px;
          padding: 16px 20px;
          font-size: 17px;
          font-weight: 900;
          cursor: pointer;
          color: #08111f;
          background: linear-gradient(90deg, #ff9b2f, #f07b1f);
          box-shadow: 0 12px 26px rgba(234, 88, 12, 0.22);
          transition: 0.2s ease;
        }

        .primary-action:hover:not(:disabled) {
          transform: translateY(-1px);
          box-shadow: 0 16px 34px rgba(234, 88, 12, 0.28);
        }

        .primary-action:disabled {
          opacity: 0.55;
          cursor: not-allowed;
        }

        .requirements-list {
          display: grid;
          gap: 12px;
        }

        .requirement-item {
          border-left: 4px solid #5ddfff;
          padding: 14px 16px;
          background: linear-gradient(90deg, rgba(13, 27, 48, 0.92), rgba(9, 19, 35, 0.92));
          border-radius: 10px;
          box-shadow: 0 8px 20px rgba(0, 0, 0, 0.14);
        }

        .requirement-item strong {
          display: block;
          color: #f3f7ff;
          font-size: 15px;
          margin-bottom: 4px;
        }

        .requirement-item span {
          color: #9bb0cb;
          font-size: 13px;
          line-height: 1.5;
        }

        .tip-box {
          margin-top: 18px;
          background: rgba(12, 24, 42, 0.94);
          border-left: 4px solid #ff9b2f;
          padding: 16px;
          border-radius: 12px;
          color: #c8d8ee;
          font-weight: 700;
          line-height: 1.5;
        }

        .upload-stats {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 16px;
          margin-top: 24px;
        }

        .stat-box {
          background: rgba(9, 18, 33, 0.92);
          border-radius: 14px;
          padding: 18px;
          box-shadow: 0 12px 30px rgba(0, 0, 0, 0.18);
          border: 1px solid rgba(148, 163, 184, 0.12);
        }

        .stat-box span {
          display: block;
          color: #9bb0cb;
          font-size: 13px;
          font-weight: 900;
        }

        .stat-box strong {
          display: block;
          margin-top: 8px;
          color: #f3f7ff;
          font-size: 24px;
        }

        .result-card {
          margin-top: 24px;
          background: rgba(9, 18, 33, 0.92);
          border-radius: 16px;
          padding: 22px;
          box-shadow: 0 12px 30px rgba(0, 0, 0, 0.18);
          border: 1px solid rgba(148, 163, 184, 0.12);
        }

        .result-card h2 {
          margin: 0 0 6px;
          color: #f3f7ff;
        }

        .result-card p {
          margin: 0 0 16px;
          color: #9bb0cb;
        }

        .table-wrap {
          overflow-x: auto;
        }

        .result-table {
          width: 100%;
          border-collapse: collapse;
          min-width: 720px;
        }

        .result-table th {
          text-align: left;
          background: rgba(12, 25, 45, 0.94);
          color: #8fe7ff;
          padding: 12px;
          font-size: 13px;
        }

        .result-table td {
          padding: 12px;
          border-bottom: 1px solid rgba(148, 163, 184, 0.08);
          color: #dcecff;
          font-size: 14px;
        }

        .empty-box {
          border: 1px dashed rgba(93, 223, 255, 0.28);
          background: rgba(12, 24, 42, 0.76);
          border-radius: 14px;
          padding: 24px;
          text-align: center;
          color: #9bb0cb;
        }

        .error-box {
          background: rgba(75, 17, 27, 0.88);
          color: #ffb1bd;
          border: 1px solid rgba(255, 107, 129, 0.24);
          border-radius: 12px;
          padding: 14px 16px;
          margin-bottom: 18px;
          font-weight: 800;
        }

        .error-list {
          display: grid;
          gap: 10px;
          margin: 0;
          padding: 0;
          list-style: none;
        }

        .error-list li {
          background: rgba(38, 19, 7, 0.92);
          border-left: 4px solid #ff9b2f;
          padding: 12px 14px;
          border-radius: 10px;
          color: #f6dac0;
        }

        @media (max-width: 980px) {
          .upload-page {
            padding: 22px;
          }

          .upload-layout {
            grid-template-columns: 1fr;
          }

          .upload-stats {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }

        @media (max-width: 620px) {
          .upload-page {
            padding: 16px;
          }

          .upload-topbar {
            align-items: flex-start;
            flex-direction: column;
          }

          .upload-title h1 {
            font-size: 26px;
          }

          .upload-card-body {
            padding: 18px;
          }

          .dropzone {
            min-height: 230px;
            padding: 20px;
          }

          .dropzone h2 {
            font-size: 18px;
          }

          .selected-file-card {
            flex-direction: column;
            align-items: flex-start;
          }

          .upload-controls,
          .upload-stats {
            grid-template-columns: 1fr;
          }
        }
      `}</style>

      <div className="upload-page">
        <div className="upload-shell">
          <div className="upload-topbar">
            <div className="upload-title">
              <h1>Upload CSV</h1>
              <p>
                Upload network traffic data, validate CSV rows, and run IDS/ML
                prediction analysis.
              </p>
            </div>

            <div className="upload-top-actions">
              <button type="button" className="link-action">
                CSV Format
              </button>
              <button type="button" className="link-action" onClick={downloadSample}>
                Sample CSV Download
              </button>
            </div>
          </div>

          {error && <div className="error-box">{error}</div>}

          <div className="upload-layout">
            <section className="upload-card">
              <div className="upload-card-header">Load network traffic data</div>

              <div className="upload-card-body">
                <div
                  className={`dropzone ${dragActive ? "active" : ""}`}
                  onClick={() => inputRef.current?.click()}
                  onDragEnter={(e) => {
                    e.preventDefault();
                    setDragActive(true);
                  }}
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragActive(true);
                  }}
                  onDragLeave={(e) => {
                    e.preventDefault();
                    setDragActive(false);
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    setDragActive(false);
                    handleSelectedFile(e.dataTransfer.files?.[0]);
                  }}
                >
                  <div>
                    <div className="dropzone-icon">CSV</div>
                    <h2>{file ? file.name : "Drop your CSV file here"}</h2>
                    <p>or click to search for and select a file</p>

                    <div className="dropzone-badges">
                      <span>CSV</span>
                      <span>Maximum 30 MB</span>
                      <span>{EXPECTED_HEADERS.length} columns</span>
                    </div>
                  </div>
                </div>

                <input
                  ref={inputRef}
                  type="file"
                  accept=".csv,text/csv"
                  className="hidden-input"
                  onChange={(e) => handleSelectedFile(e.target.files?.[0])}
                />

                {file && (
                  <div className="selected-file-card">
                    <div>
                      <strong>{file.name}</strong>
                      <span>
                        Size: {(file.size / 1024).toFixed(2)} KB | Type:{" "}
                        {file.type || "text/csv"}
                      </span>
                    </div>
                    <button type="button" className="clear-link" onClick={clearUpload}>
                      Clear
                    </button>
                  </div>
                )}

                {(uploading || progress > 0) && (
                  <div className="progress-wrap">
                    <div className="progress-track">
                      <div className="progress-fill" style={{ width: `${progress}%` }}>
                        {progress}%
                      </div>
                    </div>
                    <p>{processingText || "Loading and processing..."}</p>
                  </div>
                )}

                <div className="upload-controls">
                  <div className="control-group">
                    <label>Prediction type</label>
                    <select
                      value={predictionType}
                      onChange={(e) => setPredictionType(e.target.value)}
                    >
                      <option value="automatic">Automatic (ML only)</option>
                      <option value="hybrid">Hybrid (Rules + ML)</option>
                      <option value="rules">Rule-based only</option>
                    </select>
                  </div>

                  <div className="control-group">
                    <label>Lot size</label>
                    <select
                      value={lotSize}
                      onChange={(e) => setLotSize(e.target.value)}
                    >
                      <option value="100">100 rows</option>
                      <option value="500">500 rows</option>
                      <option value="1000">1000 rows</option>
                      <option value="5000">5000 rows</option>
                    </select>
                  </div>
                </div>

                <button
                  type="button"
                  className="primary-action"
                  onClick={handleUpload}
                  disabled={!file || uploading}
                >
                  {uploading ? "Analyzing..." : "Start analysis"}
                </button>
              </div>
            </section>

            <aside className="upload-card">
              <div className="upload-card-header">File requirements</div>

              <div className="upload-card-body">
                <div className="requirements-list">
                  <div className="requirement-item">
                    <strong>File Format</strong>
                    <span>File only CSV with .csv extension.</span>
                  </div>

                  <div className="requirement-item">
                    <strong>File Size</strong>
                    <span>Maximum 30 MB per upload.</span>
                  </div>

                  <div className="requirement-item">
                    <strong>Data structure</strong>
                    <span>It must contain structured IDS columns for analysis.</span>
                  </div>

                  <div className="requirement-item">
                    <strong>Columns</strong>
                    <span>{EXPECTED_HEADERS.join(", ")}</span>
                  </div>
                </div>

                <div className="tip-box">
                  Tip: Download the sample CSV file to see the exact format required.
                </div>
              </div>
            </aside>
          </div>

          <div className="upload-stats">
            <div className="stat-box">
              <span>Detected Headers</span>
              <strong>{validation.detectedHeaders.length}</strong>
            </div>

            <div className="stat-box">
              <span>Valid Rows</span>
              <strong>{validation.validRows}</strong>
            </div>

            <div className="stat-box">
              <span>Invalid Rows</span>
              <strong>{validation.invalidRows.length}</strong>
            </div>

            <div className="stat-box">
              <span>Uploaded Rows</span>
              <strong>{predictionRows.length || result?.meta?.insertedCount || 0}</strong>
            </div>
          </div>

          <section className="result-card">
            <h2>Prediction Result</h2>
            <p>Uploaded events processed by your IDS detection pipeline.</p>

            {predictionRows.length ? (
              <div className="table-wrap">
                <table className="result-table">
                  <thead>
                    <tr>
                      <th>Message</th>
                      <th>Source</th>
                      <th>Protocol</th>
                      <th>Severity</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>

                  <tbody>
                    {predictionRows.slice(0, 12).map((row, index) => (
                      <tr key={row._id || row.id || index}>
                        <td>{row.message || row.prediction || row.eventType || "Processed row"}</td>
                        <td>{row.source || row.metadata?.sensorType || "upload"}</td>
                        <td>{row.protocol || row.metadata?.protocol || "-"}</td>
                        <td>{row.severity || row.metadata?.idsEngine?.severity || "-"}</td>
                        <td>
                          {row.timestamp
                            ? new Date(row.timestamp).toLocaleString()
                            : "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : hasUploadResult ? (
              <div className="empty-box">
                Upload completed successfully. The backend accepted the file, but no row-by-row
                prediction list was returned for display.
              </div>
            ) : (
              <div className="empty-box">
                No prediction output yet. Upload a CSV file to see results here.
              </div>
            )}
          </section>

          <section className="result-card">
            <h2>Invalid Rows & Errors</h2>
            <p>Local CSV validation issues and upload-time problems appear here.</p>

            {[...validation.invalidRows, ...uploadErrors].length ? (
              <ul className="error-list">
                {[...validation.invalidRows, ...uploadErrors].map((entry, index) => (
                  <li key={`${entry.rowNumber || "error"}-${index}`}>
                    <strong>
                      {entry.rowNumber ? `Row ${entry.rowNumber}` : "Upload Error"}
                    </strong>
                    <div>{entry.message || entry.error || JSON.stringify(entry)}</div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="empty-box">No invalid rows detected.</div>
            )}
          </section>
        </div>
      </div>
    </MainLayout>
  );
};

export default Upload;
