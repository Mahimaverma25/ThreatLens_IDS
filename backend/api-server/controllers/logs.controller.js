const fs = require("fs/promises");
const { parse } = require("csv-parse/sync");

const Log = require("../models/Log");
const { analyzeLogs } = require("../services/detection.service");
const { createDetectionAlert } = require("../services/detection.service");
const { enqueueDetectionJob } = require("../services/detection-queue.service");
const { publishEvent } = require("../services/event-stream.service");
const { normalizeSecurityEvent, toSafeNumber } = require("../services/normalization.service");
const { appLogger, serializeError } = require("../utils/logger");
const {
  emitDashboardUpdate,
  emitNewLog,
  emitStreamEvent,
} = require("../services/socket.service");

const clampInt = (value, fallback, min, max) => {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
};

const MAX_SEARCH_LENGTH = 100;

const escapeRegex = (value = "") =>
  String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const DATASET_REQUIRED_HEADERS = [
  "protocol_type",
  "src_bytes",
  "dst_bytes",
  "count",
  "serror_rate",
  "label",
];

const normalizeHeader = (value = "") =>
  String(value || "")
    .trim()
    .replace(/^\uFEFF/, "")
    .toLowerCase();

const csvDatasetHasRequiredHeaders = (headers = []) =>
  DATASET_REQUIRED_HEADERS.every((header) => headers.includes(header));

const toNumberOrDefault = (value, fallback = 0) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const toOptionalText = (value, fallback = "") => {
  const normalized = String(value ?? fallback).trim();
  return normalized;
};

const normalizeAttackType = (value = "") => {
  const normalized = String(value || "").trim();
  if (!normalized) return "Normal";

  const lower = normalized.toLowerCase();
  if (["normal", "benign", "0"].includes(lower)) return "Normal";
  if (lower.includes("ddos") || lower.includes("dos")) return "DDoS";
  if (lower.includes("brute")) return "Brute Force";
  if (lower.includes("port")) return "Port Scan";
  return normalized;
};

const toSeverityLabel = (value = "low") => {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical") return "Critical";
  if (normalized === "high") return "High";
  if (normalized === "medium") return "Medium";
  return "Low";
};

const toSeverityLower = (value = "low") => String(value || "low").toLowerCase();

const parseDatasetCsv = (content) => {
  const rows = parse(content, {
    bom: true,
    skip_empty_lines: true,
    trim: true,
    relax_column_count: true,
  });

  if (!Array.isArray(rows) || rows.length === 0) {
    return {
      detectedHeaders: [],
      invalidRows: [{ rowNumber: 0, message: "CSV file is empty." }],
      items: [],
      isDatasetCsv: false,
    };
  }

  const detectedHeaders = (rows[0] || []).map(normalizeHeader);
  const invalidRows = [];
  const isDatasetCsv = csvDatasetHasRequiredHeaders(detectedHeaders);

  if (!isDatasetCsv) {
    const parsedItems = parse(content, {
      bom: true,
      columns: true,
      skip_empty_lines: true,
      trim: true,
    });

    return {
      detectedHeaders,
      invalidRows: invalidRows.concat(
        DATASET_REQUIRED_HEADERS.filter((header) => !detectedHeaders.includes(header)).length
          ? [
              {
                rowNumber: 1,
                message: `Missing required dataset columns: ${DATASET_REQUIRED_HEADERS.filter(
                  (header) => !detectedHeaders.includes(header)
                ).join(", ")}`,
              },
            ]
          : []
      ),
      items: parsedItems,
      isDatasetCsv: false,
    };
  }

  const items = rows.slice(1).reduce((acc, values, index) => {
    const rowNumber = index + 2;

    if (!Array.isArray(values) || values.length !== detectedHeaders.length) {
      invalidRows.push({
        rowNumber,
        message: "Column count does not match the header row.",
      });
      return acc;
    }

    const row = detectedHeaders.reduce((result, header, headerIndex) => {
      result[header] = values[headerIndex];
      return result;
    }, {});

    if (!toOptionalText(row.protocol_type)) {
      invalidRows.push({ rowNumber, message: "protocol_type is required." });
      return acc;
    }

    acc.push({
      ...row,
      __rowNumber: rowNumber,
    });
    return acc;
  }, []);

  return {
    detectedHeaders,
    invalidRows,
    items,
    isDatasetCsv: true,
  };
};

const transformDatasetRowToLog = (row, req) => {
  const protocol = toOptionalText(row.protocol_type).toUpperCase();
  const srcBytes = toNumberOrDefault(row.src_bytes, 0);
  const dstBytes = toNumberOrDefault(row.dst_bytes, 0);
  const requestCount = toNumberOrDefault(row.count, 0);
  const errorRate = toNumberOrDefault(row.serror_rate, 0);
  const attackType = normalizeAttackType(row.label);
  const failedAttempts = toNumberOrDefault(
    row.failed_logins ?? row.failed_attempts ?? row.num_failed_logins,
    0
  );
  const sourceIp = toOptionalText(
    row.source_ip || row.src_ip || row.srcip || row.src_host || req.ip,
    req.ip
  );
  const destinationIp = toOptionalText(
    row.destination_ip || row.dst_ip || row.dstip || row.dst_host,
    ""
  );
  const destinationPort = toSafeNumber(
    row.destination_port ??
      row.dest_port ??
      row.dst_port ??
      row.service_port ??
      row.port
  );

  return {
    message: "Network event detected",
    source: "upload",
    eventType: "network.upload",
    protocol,
    ip: sourceIp,
    destinationIp,
    destinationPort,
    metadata: {
      protocol,
      sourceIp,
      destinationIp,
      destinationPort,
      srcBytes,
      dstBytes,
      bytes: srcBytes + dstBytes,
      requestCount,
      requestRate: requestCount,
      flowCount: requestCount,
      errorRate,
      failedAttempts,
      attackType,
      attackLabel: toOptionalText(row.label),
      originalRow: row,
    },
    timestamp: new Date(),
  };
};

const buildPredictionFromStoredLog = ({ log, idsResult, fallbackPrediction }) => {
  const mlAnalysis = idsResult?.analysis || null;
  const metadata = log?.metadata || {};
  const idsMetadata = metadata.idsEngine || {};

  const predictedAttackType =
    fallbackPrediction?.attackType ||
    metadata.attackType ||
    mlAnalysis?.submodels?.random_forest?.predicted_class ||
    idsMetadata?.predictedClass ||
    (mlAnalysis?.is_anomaly ? "ML Behavioral Anomaly" : "Normal");

  const severity =
    fallbackPrediction?.severity ||
    mlAnalysis?.severity ||
    idsMetadata?.severity ||
    (predictedAttackType === "Normal" ? "Low" : "Medium");

  return {
    id: log._id?.toString?.() || log.eventId,
    message: fallbackPrediction?.message || log.message || "Network event detected",
    protocol:
      metadata.protocol ||
      metadata.normalized?.protocol ||
      log.protocol ||
      "-",
    severity: toSeverityLower(severity),
    attackType: predictedAttackType,
    sourceIp:
      metadata.sourceIp ||
      metadata.normalized?.srcIp ||
      log.ip ||
      "-",
    timestamp: log.timestamp,
    confidence:
      mlAnalysis?.confidence ??
      idsMetadata?.confidence ??
      null,
  };
};

const deriveFallbackPrediction = async (log) => {
  const errorRate = toNumberOrDefault(log?.metadata?.errorRate, 0);
  const failedAttempts = toNumberOrDefault(log?.metadata?.failedAttempts, 0);
  const requestCount = toNumberOrDefault(log?.metadata?.requestCount, 0);

  if (errorRate > 0.9) {
    await createDetectionAlert({
      log,
      type: "DDoS / DoS",
      attackType: "DDoS",
      severity: "Critical",
      source: "rule-engine",
      metadata: {
        family: "csv-ddos",
        errorRate,
        requestCount,
      },
    });

    return {
      attackType: "DDoS",
      severity: "high",
      message: "Potential DDoS behavior detected from CSV telemetry",
    };
  }

  if (failedAttempts > 3) {
    await createDetectionAlert({
      log,
      type: "Brute Force",
      attackType: "Brute Force",
      severity: "High",
      source: "rule-engine",
      metadata: {
        family: "csv-brute-force",
        failedAttempts,
      },
    });

    return {
      attackType: "Brute Force",
      severity: "high",
      message: "Brute force pattern detected from CSV telemetry",
    };
  }

  if (requestCount > 20) {
    await createDetectionAlert({
      log,
      type: "Port Scan",
      attackType: "Port Scan",
      severity: "Medium",
      source: "rule-engine",
      metadata: {
        family: "csv-port-scan",
        requestCount,
      },
    });

    return {
      attackType: "Port Scan",
      severity: "medium",
      message: "Port scanning behavior detected from CSV telemetry",
    };
  }

  return {
    attackType: log?.metadata?.attackType || "Normal",
    severity: "low",
    message: log?.message || "Network event detected",
  };
};

const parseJsonLine = (line) => {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
};

const parsePlainTextLogs = (content = "") =>
  content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => parseJsonLine(line) || { message: line, source: "upload" });

const parseUploadedItems = (file, content) => {
  const fileName = String(file?.originalname || "").toLowerCase();
  const mimeType = String(file?.mimetype || "").toLowerCase();

  if (mimeType.includes("json") || fileName.endsWith(".json")) {
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [parsed];
  }

  if (fileName.endsWith(".ndjson")) {
    return content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const parsed = parseJsonLine(line);
        if (!parsed || typeof parsed !== "object") {
          throw new Error("Invalid NDJSON");
        }
        return parsed;
      });
  }

  if (fileName.endsWith(".log") || fileName.endsWith(".txt")) {
    return parsePlainTextLogs(content);
  }

  return parse(content, { columns: true, skip_empty_lines: true });
};

const buildSnortLogMatch = () => ({
  $or: [
    { source: "snort" },
    { source: "suricata" },
    { "metadata.sensorType": { $in: ["snort", "suricata"] } },
    { "metadata.snort": { $exists: true, $ne: null } },
  ],
});

const getBulkUpsertedIndexes = (result) => {
  const upsertedIds =
    result?.upsertedIds ||
    result?.result?.upsertedIds ||
    result?.result?.upserted ||
    result?.upserted ||
    [];

  if (Array.isArray(upsertedIds)) {
    return upsertedIds
      .map((item) => Number(item?.index))
      .filter((value) => Number.isInteger(value) && value >= 0);
  }

  return Object.keys(upsertedIds)
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value >= 0);
};

const isDuplicateOnlyBulkError = (error) =>
  error?.code === 11000 ||
  (Array.isArray(error?.writeErrors) &&
    error.writeErrors.length > 0 &&
    error.writeErrors.every((entry) => entry?.code === 11000));

const normalizeLogEntry = (item, context = {}) => {
  let normalized = normalizeSecurityEvent(item, context);
  const sensorType = String(
    item?.sensorType ||
      item?.metadata?.sensorType ||
      item?.sensor_type ||
      normalized?.metadata?.sensorType ||
      normalized?.source ||
      context.defaultSource ||
      "unknown"
  )
    .trim()
    .toLowerCase();

  // If this is a backend/API log, ensure all table columns are present with placeholders
  if (normalized.source === "backend" || normalized.source === "api" || normalized.endpoint) {
    normalized = {
      ...normalized,
      signature: "-",
      classification: "-",
      priority: "-",
      protocol: normalized.method ? normalized.method.toUpperCase() : "-",
      sourceIp: normalized.ip || "-",
      destinationIp: "-",
      destPort: "-",
      // timestamp is already present
    };
    // Also ensure metadata has these fields for frontend compatibility
    normalized.metadata = {
      ...normalized.metadata,
      signature: "-",
      classification: "-",
      priority: "-",
      protocol: normalized.method ? normalized.method.toUpperCase() : "-",
      sourceIp: normalized.ip || "-",
      destinationIp: "-",
      destPort: "-",
    };
  }

  if (normalized.metadata?.destinationPort !== undefined) {
    normalized.metadata.destinationPort = toSafeNumber(normalized.metadata.destinationPort);
  }

  if (normalized.metadata?.port !== undefined) {
    normalized.metadata.port = toSafeNumber(normalized.metadata.port);
  }

  normalized.metadata = {
    ...(normalized.metadata || {}),
    sensorType,
    pipeline: normalized.metadata?.pipeline || "realtime",
  };

  return normalized;
};

const emitLogsCreated = ({ orgId, logs, source, duplicateCount = 0, mode = "live" }) => {
  if (!logs.length) return;

  emitNewLog(orgId, logs[0], {
    insertedCount: logs.length,
    duplicateCount,
    source,
    mode,
    items: logs.slice(0, 5),
  });

  emitDashboardUpdate(orgId, {
    source,
    mode,
    insertedCount: logs.length,
    duplicateCount,
    lastLog: logs[0] || null,
  });

  emitStreamEvent(orgId, {
    type: "telemetry.batch.persisted",
    source,
    mode,
    duplicateCount,
    insertedCount: logs.length,
    sensorTypes: [...new Set(logs.map((log) => log?.metadata?.sensorType).filter(Boolean))],
    latestEvent: logs[0] || null,
  });
};

const runDetections = async (logs) => analyzeLogs(logs);

const persistLogs = async (entries, { orgId, source, mode, asyncDetections = false }) => {
  const deduped = [];
  const seenEventIds = new Set();
  let duplicateCount = 0;

  entries.forEach((entry) => {
    if (!entry.message) return;

    if (seenEventIds.has(entry.eventId)) {
      duplicateCount += 1;
      return;
    }

    seenEventIds.add(entry.eventId);
    deduped.push(entry);
  });

  if (deduped.length === 0) {
    return {
      stored: [],
      duplicateCount,
      insertedCount: 0,
      idsAnalysis: { status: "skipped", analyzed: 0 },
    };
  }

  const operations = deduped.map((entry) => ({
    updateOne: {
      filter: {
        _org_id: entry._org_id,
        eventId: entry.eventId,
      },
      update: {
        $setOnInsert: entry,
      },
      upsert: true,
    },
  }));

  let bulkResult;

  try {
    bulkResult = await Log.bulkWrite(operations, { ordered: false });
  } catch (error) {
    if (!isDuplicateOnlyBulkError(error)) {
      throw error;
    }
    bulkResult = error.result || error;
  }

  const upsertIndexes = getBulkUpsertedIndexes(bulkResult);
  const insertedEventIds = upsertIndexes.map((index) => deduped[index]?.eventId).filter(Boolean);

  const stored = insertedEventIds.length
    ? await Log.find({
        _org_id: orgId,
        eventId: { $in: insertedEventIds },
      }).sort({ timestamp: -1 })
    : [];

  duplicateCount += deduped.length - stored.length;

  const idsAnalysis = asyncDetections
    ? (() => {
        const { queued, queueDepth } = enqueueDetectionJob({
          orgId,
          logIds: stored.map((log) => log._id),
          onError: (error) => {
            appLogger.error("Background detection job failed", serializeError(error));
          },
        });

        return {
          status: queued ? "queued" : "skipped",
          analyzed: 0,
          results: [],
          detections: 0,
          queueDepth,
        };
      })()
    : await runDetections(stored);

  await publishEvent("telemetry.batch.persisted", {
    organizationId: orgId?.toString?.() || orgId || null,
    source,
    mode,
    insertedCount: stored.length,
    duplicateCount,
    sensorTypes: [...new Set(stored.map((log) => log?.metadata?.sensorType).filter(Boolean))],
    latestEvent: stored[0]
      ? {
          id: stored[0]._id?.toString?.() || null,
          message: stored[0].message,
          source: stored[0].source,
          timestamp: stored[0].timestamp,
          sensorType: stored[0]?.metadata?.sensorType || stored[0].source,
        }
      : null,
  });

  emitLogsCreated({
    orgId,
    logs: stored,
    source,
    duplicateCount,
    mode,
  });

  return {
    stored,
    duplicateCount,
    insertedCount: stored.length,
    idsAnalysis,
  };
};

const listLogs = async (req, res) => {
  try {
    const limit = clampInt(req.query.limit || "50", 50, 1, 200);
    const page = clampInt(req.query.page || "1", 1, 1, 1000000);
    const skip = (page - 1) * limit;

    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }


    const filters = { _org_id: req.orgId };
    const explicitSource = String(req.query.source || "").trim();

    if (req.query.level) filters.level = req.query.level;
    if (explicitSource) {
      if (explicitSource === "snort") {
        Object.assign(filters, buildSnortLogMatch());
      } else if (explicitSource === "upload") {
        filters.source = "upload";
      } else if (explicitSource === "backend") {
        // Show logs generated by backend requests
        filters.source = "backend";
      } else {
        filters.source = explicitSource;
      }
    }
    if (req.query.ip) filters.ip = req.query.ip;
    if (req.query.protocol) {
      filters.$or = [
        { "metadata.protocol": req.query.protocol },
        { "metadata.appProtocol": req.query.protocol },
        { "metadata.snort.protocol": req.query.protocol },
      ];
    }
    if (req.query.destinationPort) {
      const destinationPort = Number.parseInt(req.query.destinationPort, 10);
      if (!Number.isNaN(destinationPort)) {
        filters.$and = filters.$and || [];
        filters.$and.push({
          $or: [
            { "metadata.destinationPort": destinationPort },
            { "metadata.port": destinationPort },
            { "metadata.snort.destPort": destinationPort },
          ],
        });
      }
    }

    const rawSearch = String(req.query.search || "").trim();
    if (rawSearch.length > MAX_SEARCH_LENGTH) {
      return res.status(400).json({ message: "Search term too long" });
    }

    if (rawSearch) {
      const safeSearch = escapeRegex(rawSearch);
      const searchFilters = [
        { message: { $regex: safeSearch, $options: "i" } },
        { eventType: { $regex: safeSearch, $options: "i" } },
        { "metadata.protocol": { $regex: safeSearch, $options: "i" } },
        { "metadata.appProtocol": { $regex: safeSearch, $options: "i" } },
        { "metadata.snort.classification": { $regex: safeSearch, $options: "i" } },
      ];

      filters.$and = filters.$and || [];
      filters.$and.push({ $or: searchFilters });
    }

    const [logs, total] = await Promise.all([
      Log.find(filters).sort({ timestamp: -1 }).skip(skip).limit(limit),
      Log.countDocuments(filters),
    ]);

    return res.json({
      data: logs,
      pagination: { total, page, limit },
    });
  } catch (error) {
    appLogger.error("Failed to list logs", serializeError(error));
    return res.status(500).json({ message: "Failed to fetch logs" });
  }
};

const createLog = async (req, res) => {
  try {
    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }

    if (!String(req.body?.message || "").trim()) {
      return res.status(400).json({ message: "Log message is required" });
    }

    const normalized = normalizeLogEntry(req.body, {
      orgId: req.orgId,
      ip: req.ip,
      defaultSource: "frontend",
    });

    normalized.userId = req.user?.sub;

    const result = await persistLogs([normalized], {
      orgId: req.orgId,
      source: normalized.source,
      mode: "manual",
    });

    return res.status(201).json({
      data: result.stored[0] || null,
      meta: {
        insertedCount: result.insertedCount,
        duplicateCount: result.duplicateCount,
        idsAnalysis: result.idsAnalysis.status,
      },
    });
  } catch (error) {
    appLogger.error("Failed to create log", serializeError(error));
    return res.status(500).json({ message: "Failed to create log" });
  }
};

const ingestLogs = async (req, res) => {
  try {
    if (!req.orgId || !req.assetId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const inputLogs = Array.isArray(req.body?.logs) ? req.body.logs : [];

    const normalizedLogs = inputLogs
      .filter((item) => item && typeof item === "object")
      .map((item) =>
        normalizeLogEntry(item, {
          orgId: req.orgId,
          assetId: req.assetId,
          assetIdentity: req.asset?.asset_id,
          hostname: req.asset?.hostname,
          ip: req.ip,
          defaultSource: item?.source || "agent",
        })
      )
      .filter((entry) => entry.message);

    if (normalizedLogs.length === 0) {
      return res.status(400).json({ message: "No valid logs to insert" });
    }

    const result = await persistLogs(normalizedLogs, {
      orgId: req.orgId,
      source: "agent",
      mode: "live-ingest",
      asyncDetections: true,
    });

    return res.status(201).json({
      success: true,
      inserted: result.insertedCount,
      duplicates: result.duplicateCount,
      idsAnalysis: result.idsAnalysis.status,
      idsAnalyzed: result.idsAnalysis.analyzed || 0,
    });
  } catch (error) {
    appLogger.error("Failed to ingest logs", serializeError(error));
    return res.status(500).json({ message: "Failed to ingest logs" });
  }
};

const uploadLogs = async (req, res) => {
  let uploadedFilePath = "";

  try {
    if (!req.file) {
      return res.status(400).json({ message: "Upload file required" });
    }

    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }

    uploadedFilePath = req.file.path || "";
    const content = await fs.readFile(uploadedFilePath, "utf8");
    let items = [];
    let detectedHeaders = [];
    let invalidRows = [];
    let isDatasetCsv = false;

    try {
      const lowerName = String(req.file.originalname || "").toLowerCase();

      if (lowerName.endsWith(".csv")) {
        const parsedCsv = parseDatasetCsv(content);
        items = parsedCsv.items;
        detectedHeaders = parsedCsv.detectedHeaders;
        invalidRows = parsedCsv.invalidRows;
        isDatasetCsv = parsedCsv.isDatasetCsv;
      } else {
        items = parseUploadedItems(req.file, content);
      }
    } catch (parseError) {
      return res.status(400).json({
        message: "Invalid file format. Supported formats: CSV, JSON, NDJSON, LOG, TXT",
      });
    }

    const normalizedLogs = items
      .filter((item) => item && typeof item === "object")
      .map((item) => {
        const inputItem = isDatasetCsv ? transformDatasetRowToLog(item, req) : item;

        return normalizeLogEntry(inputItem, {
          orgId: req.orgId,
          assetIdentity: req.asset?.asset_id,
          hostname: req.asset?.hostname,
          ip: req.ip,
          defaultSource: "upload",
        });
      })
      .filter((entry) => entry.message);

    if (normalizedLogs.length === 0) {
      return res.status(400).json({
        message: "No valid log entries were found in the uploaded file",
      });
    }

    const result = await persistLogs(normalizedLogs, {
      orgId: req.orgId,
      source: "upload",
      mode: "upload",
    });

    const idsResultsByEventId = new Map(
      Array.isArray(result.idsAnalysis?.results)
        ? result.idsAnalysis.results
            .filter((item) => item?.event_id)
            .map((item) => [item.event_id, item])
        : []
    );

    const predictions = [];
    const shouldUseFallbackRules =
      isDatasetCsv &&
      (!result.idsAnalysis ||
        result.idsAnalysis.status === "offline" ||
        result.idsAnalysis.status === "rules-only");

    for (const storedLog of result.stored) {
      const idsResult = idsResultsByEventId.get(storedLog.eventId || storedLog._id?.toString?.());
      const fallbackPrediction = shouldUseFallbackRules
        ? await deriveFallbackPrediction(storedLog)
        : null;

      predictions.push(
        buildPredictionFromStoredLog({
          log: storedLog,
          idsResult,
          fallbackPrediction,
        })
      );
    }

    return res.status(201).json({
      data: result.stored,
      predictions,
      meta: {
        insertedCount: result.insertedCount,
        duplicateCount: result.duplicateCount,
        idsAnalysis: result.idsAnalysis.status,
        detectedHeaders,
        invalidRows,
        fileName: req.file.originalname,
        fileType: req.file.mimetype || "text/plain",
      },
    });
  } catch (error) {
    appLogger.error("Failed to upload logs", serializeError(error));
    return res.status(500).json({
      message:
        error?.message?.includes("Unsupported file type") ||
        error?.message?.includes("Invalid upload MIME type") ||
        error?.message?.includes("Invalid CSV upload type")
          ? error.message
          : "Failed to upload logs",
    });
  } finally {
    if (uploadedFilePath) {
      await fs.unlink(uploadedFilePath).catch(() => {});
    }
  }
};

module.exports = {
  listLogs,
  createLog,
  ingestLogs,
  uploadLogs,
};
