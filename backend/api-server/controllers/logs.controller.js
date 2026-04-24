const { parse } = require("csv-parse/sync");

const Log = require("../models/Log");
const { analyzeLogs } = require("../services/detection.service");
const { publishEvent } = require("../services/event-stream.service");
const { normalizeSecurityEvent, toSafeNumber } = require("../services/normalization.service");
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

const runDetections = async (logs) => {
  return analyzeLogs(logs);
};

const persistLogs = async (entries, { orgId, source, mode }) => {
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

  const idsAnalysis = await runDetections(stored);

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

    if (req.query.search) {
      const searchFilters = [
        { message: { $regex: req.query.search, $options: "i" } },
        { eventType: { $regex: req.query.search, $options: "i" } },
        { "metadata.protocol": { $regex: req.query.search, $options: "i" } },
        { "metadata.appProtocol": { $regex: req.query.search, $options: "i" } },
        { "metadata.snort.classification": { $regex: req.query.search, $options: "i" } },
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
    console.error("listLogs error:", error);
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
    console.error("createLog error:", error);
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
    });

    return res.status(201).json({
      success: true,
      inserted: result.insertedCount,
      duplicates: result.duplicateCount,
      idsAnalysis: result.idsAnalysis.status,
      idsAnalyzed: result.idsAnalysis.analyzed || 0,
    });
  } catch (error) {
    console.error("ingestLogs error:", error);
    return res.status(500).json({ message: "Failed to ingest logs" });
  }
};

const uploadLogs = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "Upload file required" });
    }

    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }

    const content = req.file.buffer.toString("utf-8");
    let items = [];

    try {
      if (req.file.mimetype.includes("json") || req.file.originalname.endsWith(".json")) {
        const parsed = JSON.parse(content);
        items = Array.isArray(parsed) ? parsed : [parsed];
      } else {
        items = parse(content, { columns: true, skip_empty_lines: true });
      }
    } catch (parseError) {
      return res.status(400).json({ message: "Invalid file format" });
    }

    const normalizedLogs = items
      .filter((item) => item && typeof item === "object")
      .map((item) =>
        normalizeLogEntry(item, {
          orgId: req.orgId,
          assetIdentity: req.asset?.asset_id,
          hostname: req.asset?.hostname,
          ip: req.ip,
          defaultSource: "upload",
        })
      )
      .filter((entry) => entry.message);

    const result = await persistLogs(normalizedLogs, {
      orgId: req.orgId,
      source: "upload",
      mode: "upload",
    });

    return res.status(201).json({
      data: result.stored,
      meta: {
        insertedCount: result.insertedCount,
        duplicateCount: result.duplicateCount,
        idsAnalysis: result.idsAnalysis.status,
      },
    });
  } catch (error) {
    console.error("uploadLogs error:", error);
    return res.status(500).json({ message: "Failed to upload logs" });
  }
};

module.exports = {
  listLogs,
  createLog,
  ingestLogs,
  uploadLogs,
};
