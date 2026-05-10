import { useMemo, useRef, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { uploads } from "../services/api";

const SAMPLE_CSV = [
  "protocol_type,src_bytes,dst_bytes,count,serror_rate,label,source_ip,destination_ip,failed_logins",
  "tcp,491,1200,28,0.96,neptune,192.168.1.12,10.10.20.7,0",
  "tcp,120,84,8,0.10,normal,192.168.1.99,10.10.20.21,0",
  "tcp,64,32,6,0.35,guess_passwd,192.168.1.44,10.10.20.45,5",
].join("\n");

const EXPECTED_HEADERS = [
  "protocol_type",
  "src_bytes",
  "dst_bytes",
  "count",
  "serror_rate",
  "label",
];

const OPTIONAL_HEADERS = [
  "source_ip",
  "destination_ip",
  "failed_logins",
  "destination_port",
];

const SUPPORTED_UPLOAD_EXTENSIONS = [".csv", ".json", ".ndjson", ".log", ".txt"];
const MAX_UPLOAD_FILE_SIZE = 100 * 1024 * 1024;

const isSupportedUploadFile = (fileName = "") =>
  SUPPORTED_UPLOAD_EXTENSIONS.some((extension) =>
    String(fileName).toLowerCase().endsWith(extension)
  );

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

const normalizeHeader = (value = "") =>
  String(value || "")
    .trim()
    .replace(/^\uFEFF/, "")
    .toLowerCase();

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

  const detectedHeaders = splitCsvLine(lines[0]).map(normalizeHeader);
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

    if (!String(row.protocol_type || "").trim()) {
      invalidRows.push({ rowNumber, message: "protocol_type is required." });
      return;
    }

    if (!String(row.label || "").trim()) {
      invalidRows.push({ rowNumber, message: "label is required." });
      return;
    }

    validRows += 1;
  });

  return { validRows, invalidRows, detectedHeaders };
};

const resolveUploadedRows = (payload) => {
  if (Array.isArray(payload?.predictions)) return payload.predictions;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.rows)) return payload.rows;
  return [];
};

const resolveDetectedHeaders = (payload) => {
  if (Array.isArray(payload?.meta?.detectedHeaders)) return payload.meta.detectedHeaders;
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

  const detectedHeaders = useMemo(() => {
    if (validation.detectedHeaders.length) return validation.detectedHeaders;
    return resolveDetectedHeaders(result);
  }, [result, validation.detectedHeaders]);

  const hasUploadResult = Boolean(result);
  const isCsvFile = file ? file.name.toLowerCase().endsWith(".csv") : false;

  const handleSelectedFile = async (nextFile) => {
    if (!nextFile) return;

    if (!isSupportedUploadFile(nextFile.name)) {
      setError("Supported files: CSV, JSON, NDJSON, LOG, and TXT.");
      return;
    }

    if (nextFile.size > MAX_UPLOAD_FILE_SIZE) {
      setError("File size must be less than 100 MB.");
      return;
    }

    setError("");
    setResult(null);
    setProgress(0);
    setProcessingText("");
    setFile(nextFile);

    try {
      if (nextFile.name.toLowerCase().endsWith(".csv")) {
        const nextValidation = await readCsvValidation(nextFile);
        setValidation(nextValidation);
      } else {
        setValidation({ validRows: 0, invalidRows: [], detectedHeaders: [] });
      }
    } catch (err) {
      console.error("Upload validation error:", err);
      setValidation({ validRows: 0, invalidRows: [], detectedHeaders: [] });
      setError("The selected file could not be read.");
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setError("Please select a file first.");
      return;
    }

    try {
      setUploading(true);
      setError("");
      setResult(null);
      setProgress(20);
      setProcessingText("Preparing telemetry file...");

      const timerOne = setTimeout(() => {
        setProgress(55);
        setProcessingText(
          isCsvFile ? "Validating CSV traffic rows..." : "Validating uploaded log entries..."
        );
      }, 350);

      const timerTwo = setTimeout(() => {
        setProgress(90);
        setProcessingText("Running ThreatLens detection analysis...");
      }, 850);

      const response = await uploads.uploadCsv(file);

      clearTimeout(timerOne);
      clearTimeout(timerTwo);

      setProgress(100);
      setProcessingText("Analysis completed successfully.");
      setResult(response?.data ?? null);

      if (isCsvFile && Array.isArray(response?.data?.meta?.detectedHeaders)) {
        setValidation((current) => ({
          ...current,
          detectedHeaders: response.data.meta.detectedHeaders,
          invalidRows: Array.isArray(response.data.meta.invalidRows)
            ? response.data.meta.invalidRows
            : current.invalidRows,
        }));
      }
    } catch (err) {
      console.error("CSV upload error:", err);
      setProgress(0);
      setProcessingText("");
      setError(err?.response?.data?.message || "Failed to analyze uploaded file.");
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

  const invalidCount = isCsvFile
    ? [...validation.invalidRows, ...uploadErrors].length
    : uploadErrors.length || 0;

  return (
    <MainLayout>
      <style>{`
        .upload-page {
          display: grid;
          gap: 24px;
        }

        .upload-header {
          display: flex;
          justify-content: space-between;
          gap: 18px;
          align-items: center;
        }

        .upload-header h1 {
          margin: 0;
          color: #f8fbff;
          font-size: 2rem;
        }

        .upload-header p {
          margin: 8px 0 0;
          max-width: 900px;
          color: #9bb0cb;
        }

        .upload-actions {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
        }

        .upload-action-btn {
          min-height: 46px;
          padding: 0 22px;
          border: none;
          border-radius: 12px;
          background: linear-gradient(135deg, #ff7a18, #e85500);
          color: #ffffff;
          font-weight: 900;
          cursor: pointer;
        }

        .upload-summary-grid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 16px;
        }

        .upload-summary-grid div {
          padding: 22px;
          border-radius: 18px;
          background: rgba(8, 17, 31, 0.84);
          border: 1px solid rgba(148, 163, 184, 0.12);
          box-shadow: 0 14px 30px rgba(2, 6, 18, 0.18);
        }

        .upload-summary-grid span {
          display: block;
          color: #9bb0cb;
          font-size: 0.85rem;
        }

        .upload-summary-grid strong {
          display: block;
          margin-top: 10px;
          color: #f8fbff;
          font-size: 1.7rem;
        }

        .upload-panel,
        .upload-result-panel {
          overflow: hidden;
          border-radius: 20px;
          background: #ffffff;
          box-shadow: 0 18px 34px rgba(2, 6, 18, 0.16);
        }

        .upload-panel-title {
          min-height: 64px;
          padding: 0 24px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          background: linear-gradient(135deg, #ff7a18, #e85500);
          color: #ffffff;
          font-weight: 900;
          font-size: 1.12rem;
        }

        .upload-panel-title h3 {
          margin: 0;
          color: #ffffff;
        }

        .upload-panel-title span {
          padding: 8px 14px;
          border-radius: 999px;
          background: #2563eb;
          color: #ffffff;
          font-size: 0.84rem;
          white-space: nowrap;
        }

        .upload-layout {
          display: grid;
          grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.85fr);
          gap: 24px;
          align-items: start;
        }

        .upload-panel-body {
          padding: 28px;
        }

        .upload-dropzone {
          min-height: 310px;
          border: 2px dashed #fb923c;
          border-radius: 18px;
          background: linear-gradient(135deg, #fff7ed, #f8fafc);
          display: grid;
          place-items: center;
          text-align: center;
          cursor: pointer;
          padding: 30px;
          transition: 0.2s ease;
        }

        .upload-dropzone:hover,
        .upload-dropzone.active {
          transform: translateY(-2px);
          border-color: #ea580c;
          box-shadow: 0 16px 30px rgba(234, 88, 12, 0.14);
        }

        .upload-dropzone-icon {
          width: 76px;
          height: 76px;
          margin: 0 auto 16px;
          display: grid;
          place-items: center;
          border-radius: 22px;
          background: linear-gradient(135deg, #ff7a18, #e85500);
          color: #ffffff;
          font-weight: 900;
          letter-spacing: 0.08em;
        }

        .upload-dropzone h2 {
          margin: 0;
          color: #1f2937;
          font-size: 1.45rem;
        }

        .upload-dropzone p {
          margin: 10px 0 18px;
          color: #64748b;
        }

        .upload-badge-row {
          display: flex;
          justify-content: center;
          gap: 8px;
          flex-wrap: wrap;
        }

        .upload-badge-row span {
          display: inline-flex;
          align-items: center;
          min-height: 32px;
          padding: 0 13px;
          border-radius: 999px;
          background: #e0f2fe;
          color: #075985;
          font-size: 0.78rem;
          font-weight: 900;
        }

        .hidden-input {
          display: none;
        }

        .upload-selected-file {
          margin-top: 18px;
          padding: 18px;
          border-radius: 16px;
          background: #f8fafc;
          border: 1px solid #e5e7eb;
          display: flex;
          justify-content: space-between;
          gap: 16px;
          align-items: center;
        }

        .upload-selected-file strong {
          display: block;
          color: #111827;
          margin-bottom: 5px;
        }

        .upload-selected-file span {
          color: #64748b;
          font-size: 0.86rem;
        }

        .upload-clear-btn {
          border: none;
          border-radius: 999px;
          padding: 9px 14px;
          background: #fee2e2;
          color: #991b1b;
          font-weight: 900;
          cursor: pointer;
        }

        .upload-progress {
          margin-top: 18px;
        }

        .upload-progress-track {
          height: 16px;
          border-radius: 999px;
          background: #e5e7eb;
          overflow: hidden;
        }

        .upload-progress-fill {
          height: 100%;
          border-radius: inherit;
          background: linear-gradient(135deg, #2563eb, #0ea5e9);
          color: #ffffff;
          font-size: 0.72rem;
          font-weight: 900;
          line-height: 16px;
          text-align: center;
          transition: width 0.3s ease;
        }

        .upload-progress p {
          margin: 9px 0 0;
          color: #64748b;
          font-weight: 700;
        }

        .upload-controls {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 18px;
          margin-top: 22px;
        }

        .upload-control-group {
          display: grid;
          gap: 8px;
        }

        .upload-control-group label {
          color: #374151;
          font-weight: 900;
          font-size: 0.86rem;
        }

        .upload-control-group select {
          min-height: 48px;
          padding: 0 14px;
          border-radius: 10px;
          border: 1px solid #e5e7eb;
          background: #ffffff;
          color: #111827;
          font-weight: 700;
        }

        .upload-primary-btn {
          width: 100%;
          min-height: 52px;
          margin-top: 22px;
          border: none;
          border-radius: 12px;
          background: linear-gradient(135deg, #ff7a18, #e85500);
          color: #ffffff;
          font-size: 1rem;
          font-weight: 900;
          cursor: pointer;
        }

        .upload-primary-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .upload-requirements {
          display: grid;
          gap: 14px;
        }

        .upload-requirement-item {
          padding: 16px;
          border-radius: 14px;
          background: #f8fafc;
          border-left: 5px solid #ff7a18;
        }

        .upload-requirement-item strong {
          display: block;
          color: #1f2937;
          margin-bottom: 5px;
        }

        .upload-requirement-item span {
          color: #64748b;
          line-height: 1.5;
          font-size: 0.88rem;
        }

        .upload-tip-box {
          margin-top: 18px;
          padding: 16px;
          border-radius: 14px;
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          color: #1e3a8a;
          font-weight: 800;
          line-height: 1.5;
        }

        .upload-stats-grid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 16px;
        }

        .upload-stats-grid div {
          padding: 20px;
          border-radius: 16px;
          background: rgba(8, 17, 31, 0.84);
          border: 1px solid rgba(148, 163, 184, 0.12);
        }

        .upload-stats-grid span {
          display: block;
          color: #9bb0cb;
          font-size: 0.84rem;
          font-weight: 800;
        }

        .upload-stats-grid strong {
          display: block;
          margin-top: 8px;
          color: #f8fbff;
          font-size: 1.8rem;
        }

        .upload-result-body {
          padding: 28px;
        }

        .upload-table-wrap {
          overflow-x: auto;
        }

        .upload-result-table {
          width: 100%;
          min-width: 980px;
          border-collapse: collapse;
        }

        .upload-result-table th {
          padding: 18px;
          text-align: left;
          background: linear-gradient(135deg, #fb923c, #ea580c);
          color: #ffffff;
          font-size: 0.86rem;
        }

        .upload-result-table td {
          padding: 18px;
          border-bottom: 1px solid #f1f5f9;
          color: #374151;
          font-weight: 700;
          vertical-align: top;
        }

        .upload-pill {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-height: 30px;
          padding: 0 12px;
          border-radius: 999px;
          font-size: 0.78rem;
          font-weight: 900;
          text-transform: uppercase;
          background: #e0f2fe;
          color: #075985;
        }

        .upload-empty-box {
          padding: 30px;
          text-align: center;
          border-radius: 16px;
          background: #f8fafc;
          color: #64748b;
          font-weight: 800;
          border: 1px dashed #cbd5e1;
        }

        .upload-error-box {
          padding: 14px 16px;
          border-radius: 14px;
          background: #fee2e2;
          color: #991b1b;
          font-weight: 900;
          border: 1px solid #fecaca;
        }

        .upload-error-list {
          display: grid;
          gap: 10px;
          margin: 0;
          padding: 0;
          list-style: none;
        }

        .upload-error-list li {
          padding: 14px;
          border-radius: 12px;
          background: #fff7ed;
          border-left: 5px solid #ea580c;
          color: #7c2d12;
          font-weight: 700;
        }

        @media (max-width: 1100px) {
          .upload-layout {
            grid-template-columns: 1fr;
          }

          .upload-summary-grid,
          .upload-stats-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }

        @media (max-width: 700px) {
          .upload-header {
            flex-direction: column;
            align-items: flex-start;
          }

          .upload-actions,
          .upload-action-btn {
            width: 100%;
          }

          .upload-summary-grid,
          .upload-stats-grid,
          .upload-controls {
            grid-template-columns: 1fr;
          }

          .upload-selected-file {
            flex-direction: column;
            align-items: flex-start;
          }

          .upload-panel-title {
            flex-direction: column;
            align-items: flex-start;
            padding: 18px 24px;
          }
        }
      `}</style>

      <section className="upload-page">
        <div className="upload-header">
          <div>
            <div className="command-eyebrow">THREATLENS / TELEMETRY INGESTION / OFFLINE ANALYSIS</div>
            <h1>Upload Telemetry</h1>
            <p>
              Upload IDS datasets, Snort logs, or host-agent telemetry files for validation,
              offline analysis, and alert generation.
            </p>
          </div>

          <div className="upload-actions">
            <button type="button" className="upload-action-btn" onClick={downloadSample}>
              Download Sample CSV
            </button>
          </div>
        </div>

        {error && <div className="upload-error-box">{error}</div>}

        <section className="upload-summary-grid">
          <div>
            <span>Supported Files</span>
            <strong>CSV / LOG</strong>
          </div>
          <div>
            <span>Maximum Size</span>
            <strong>100 MB</strong>
          </div>
          <div>
            <span>Detection Mode</span>
            <strong>{predictionType}</strong>
          </div>
          <div>
            <span>Processing Status</span>
            <strong>{uploading ? "Running" : hasUploadResult ? "Done" : "Ready"}</strong>
          </div>
        </section>

        <div className="upload-layout">
          <section className="upload-panel">
            <div className="upload-panel-title">
              <h3>▦ Upload Telemetry File</h3>
              <span>{file ? "File selected" : "Awaiting file"}</span>
            </div>

            <div className="upload-panel-body">
              <div
                className={`upload-dropzone ${dragActive ? "active" : ""}`}
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
                  <div className="upload-dropzone-icon">{file ? "FILE" : "LOG"}</div>
                  <h2>{file ? file.name : "Drop telemetry file here"}</h2>
                  <p>Click to browse or drag a CSV, JSON, NDJSON, LOG, or TXT file.</p>

                  <div className="upload-badge-row">
                    <span>CSV / JSON / NDJSON</span>
                    <span>Snort LOG / TXT</span>
                    <span>100 MB Max</span>
                    <span>{EXPECTED_HEADERS.length} CSV Required Fields</span>
                  </div>
                </div>
              </div>

              <input
                ref={inputRef}
                type="file"
                accept=".csv,.json,.ndjson,.log,.txt,text/csv,application/json,text/plain"
                className="hidden-input"
                onChange={(e) => handleSelectedFile(e.target.files?.[0])}
              />

              {file && (
                <div className="upload-selected-file">
                  <div>
                    <strong>{file.name}</strong>
                    <span>
                      Size: {(file.size / 1024).toFixed(2)} KB | Type:{" "}
                      {file.type || "text/plain"}
                    </span>
                  </div>

                  <button type="button" className="upload-clear-btn" onClick={clearUpload}>
                    Clear
                  </button>
                </div>
              )}

              {(uploading || progress > 0) && (
                <div className="upload-progress">
                  <div className="upload-progress-track">
                    <div
                      className="upload-progress-fill"
                      style={{ width: `${progress}%` }}
                    >
                      {progress}%
                    </div>
                  </div>
                  <p>{processingText || "Processing telemetry..."}</p>
                </div>
              )}

              <div className="upload-controls">
                <div className="upload-control-group">
                  <label>Detection Mode</label>
                  <select
                    value={predictionType}
                    onChange={(e) => setPredictionType(e.target.value)}
                  >
                    <option value="automatic">Automatic Detection</option>
                    <option value="hybrid">Hybrid Pipeline</option>
                    <option value="rules">Rule-Based Analysis</option>
                  </select>
                </div>

                <div className="upload-control-group">
                  <label>Batch Size</label>
                  <select value={lotSize} onChange={(e) => setLotSize(e.target.value)}>
                    <option value="100">100 rows</option>
                    <option value="500">500 rows</option>
                    <option value="1000">1000 rows</option>
                    <option value="5000">5000 rows</option>
                  </select>
                </div>
              </div>

              <button
                type="button"
                className="upload-primary-btn"
                onClick={handleUpload}
                disabled={!file || uploading}
              >
                {uploading ? "Analyzing..." : "Start ThreatLens Analysis"}
              </button>
            </div>
          </section>

          <aside className="upload-panel">
            <div className="upload-panel-title">
              <h3>▦ File Requirements</h3>
              <span>Validation rules</span>
            </div>

            <div className="upload-panel-body">
              <div className="upload-requirements">
                <div className="upload-requirement-item">
                  <strong>Supported Format</strong>
                  <span>CSV, JSON, NDJSON, LOG, and TXT files are supported.</span>
                </div>

                <div className="upload-requirement-item">
                  <strong>Maximum File Size</strong>
                  <span>Maximum 100 MB per upload for offline analysis.</span>
                </div>

                <div className="upload-requirement-item">
                  <strong>Required CSV Columns</strong>
                  <span>{EXPECTED_HEADERS.join(", ")}</span>
                </div>

                <div className="upload-requirement-item">
                  <strong>Optional Enrichment Fields</strong>
                  <span>{OPTIONAL_HEADERS.join(", ")}</span>
                </div>
              </div>

              <div className="upload-tip-box">
                Tip: Use the sample CSV to test upload detection before uploading a larger IDS dataset.
              </div>
            </div>
          </aside>
        </div>

        <section className="upload-stats-grid">
          <div>
            <span>Detected Headers</span>
            <strong>{isCsvFile ? detectedHeaders.length : "-"}</strong>
          </div>

          <div>
            <span>Valid Rows</span>
            <strong>{isCsvFile ? validation.validRows : "-"}</strong>
          </div>

          <div>
            <span>Invalid Rows</span>
            <strong>{isCsvFile ? invalidCount : uploadErrors.length || "-"}</strong>
          </div>

          <div>
            <span>Uploaded Rows</span>
            <strong>{predictionRows.length || result?.meta?.insertedCount || 0}</strong>
          </div>
        </section>

        <section className="upload-result-panel">
          <div className="upload-panel-title">
            <h3>▦ Detection Result</h3>
            <span>{predictionRows.length || result?.meta?.insertedCount || 0} rows</span>
          </div>

          <div className="upload-result-body">
            {predictionRows.length ? (
              <div className="upload-table-wrap">
                <table className="upload-result-table">
                  <thead>
                    <tr>
                      <th>Protocol</th>
                      <th>Severity</th>
                      <th>Attack Type</th>
                      <th>Source IP</th>
                      <th>Message</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>

                  <tbody>
                    {predictionRows.slice(0, 12).map((row, index) => (
                      <tr key={row._id || row.id || index}>
                        <td>
                          <span className="upload-pill">
                            {row.protocol || row.metadata?.protocol || "-"}
                          </span>
                        </td>
                        <td>{row.severity || row.metadata?.idsEngine?.severity || "-"}</td>
                        <td>
                          {row.attackType ||
                            row.metadata?.attackType ||
                            row.metadata?.idsEngine?.predictedClass ||
                            "-"}
                        </td>
                        <td className="mono">
                          {row.sourceIp || row.metadata?.sourceIp || row.ip || "-"}
                        </td>
                        <td>{row.message || "Network event detected"}</td>
                        <td>
                          {row.timestamp ? new Date(row.timestamp).toLocaleString() : "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : hasUploadResult ? (
              <div className="upload-empty-box">
                Upload completed successfully. Backend accepted the file, but no row-by-row prediction list was returned.
              </div>
            ) : (
              <div className="upload-empty-box">
                No output yet. Upload a telemetry file to see detection results here.
              </div>
            )}
          </div>
        </section>

        <section className="upload-result-panel">
          <div className="upload-panel-title">
            <h3>▦ Detected Headers</h3>
            <span>{detectedHeaders.length || 0} headers</span>
          </div>

          <div className="upload-result-body">
            {isCsvFile && detectedHeaders.length ? (
              <div className="upload-badge-row">
                {detectedHeaders.map((header) => (
                  <span key={header}>{header}</span>
                ))}
              </div>
            ) : (
              <div className="upload-empty-box">No CSV headers detected yet.</div>
            )}
          </div>
        </section>

        <section className="upload-result-panel">
          <div className="upload-panel-title">
            <h3>▦ Invalid Rows & Errors</h3>
            <span>{[...validation.invalidRows, ...uploadErrors].length} issues</span>
          </div>

          <div className="upload-result-body">
            {[...validation.invalidRows, ...uploadErrors].length ? (
              <ul className="upload-error-list">
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
              <div className="upload-empty-box">No invalid rows detected.</div>
            )}
          </div>
        </section>
      </section>
    </MainLayout>
  );
};

export default Upload;