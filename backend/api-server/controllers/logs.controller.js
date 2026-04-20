const { parse } = require("csv-parse/sync");

const Log = require("../models/Log");
const config = require("../config/env");
const { evaluateLog } = require("../services/detector.service");
const { analyzeLogs } = require("../services/detection.service");
const { generateTrafficBatch } = require("../services/traffic.service");
const { emitToOrganization } = require("../socket");
const { sha256 } = require("../utils/ingestSignature");

const clampInt = (value, fallback, min, max) => {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
};

const normalizeTimestamp = (value) => {
  const parsed = new Date(value || Date.now());
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
};

const sanitizeMetadata = (metadata) =>
  metadata && typeof metadata === "object" && !Array.isArray(metadata) ? metadata : {};

const buildSnortLogMatch = () => ({
  $or: [{ source: "snort" }, { "metadata.snort": { $exists: true, $ne: null } }],
});

const truncateTimestampToSecond = (timestamp) => {
  const value = new Date(timestamp || Date.now());
  value.setMilliseconds(0);
  return value.toISOString();
};

const toSafeNumber = (value) => {
  if (value === null || value === undefined || value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

const buildEventFingerprint = (normalizedLog) =>
  sha256(
    JSON.stringify(
      normalizedLog.source === "snort" || normalizedLog.metadata?.snort
        ? {
            source: "snort",
            eventType: normalizedLog.eventType || "snort.alert",
            timestamp: truncateTimestampToSecond(normalizedLog.timestamp),
            message: normalizedLog.message,
            protocol:
              normalizedLog.metadata?.protocol ||
              normalizedLog.metadata?.appProtocol ||
              normalizedLog.metadata?.snort?.protocol ||
              null,
            snort: {
              generatorId: normalizedLog.metadata?.snort?.generatorId || null,
              signatureId: normalizedLog.metadata?.snort?.signatureId || null,
              revision: normalizedLog.metadata?.snort?.revision || null,
              classification: normalizedLog.metadata?.snort?.classification || null,
              priority: normalizedLog.metadata?.snort?.priority || null,
              srcIp: normalizedLog.metadata?.snort?.srcIp || normalizedLog.ip || null,
              srcPort: normalizedLog.metadata?.snort?.srcPort || null,
              destIp: normalizedLog.metadata?.snort?.destIp || null,
              destPort:
                normalizedLog.metadata?.snort?.destPort ??
                normalizedLog.metadata?.destinationPort ??
                normalizedLog.metadata?.port ??
                null,
            },
          }
        : {
            assetId: normalizedLog._asset_id?.toString?.() || normalizedLog._asset_id || null,
            source: normalizedLog.source,
            eventType: normalizedLog.eventType || null,
            message: normalizedLog.message,
            ip: normalizedLog.ip || null,
            endpoint: normalizedLog.endpoint || null,
            method: normalizedLog.method || null,
            statusCode: normalizedLog.statusCode || null,
            timestamp: normalizedLog.timestamp.toISOString(),
            protocol:
              normalizedLog.metadata?.protocol ||
              normalizedLog.metadata?.appProtocol ||
              normalizedLog.metadata?.snort?.protocol ||
              null,
            destinationPort:
              normalizedLog.metadata?.destinationPort ??
              normalizedLog.metadata?.port ??
              normalizedLog.metadata?.snort?.destPort ??
              null,
            snort: normalizedLog.metadata?.snort
              ? {
                  generatorId: normalizedLog.metadata.snort.generatorId || null,
                  signatureId: normalizedLog.metadata.snort.signatureId || null,
                  revision: normalizedLog.metadata.snort.revision || null,
                  classification: normalizedLog.metadata.snort.classification || null,
                  priority: normalizedLog.metadata.snort.priority || null,
                  srcIp: normalizedLog.metadata.snort.srcIp || null,
                  srcPort: normalizedLog.metadata.snort.srcPort || null,
                  destIp: normalizedLog.metadata.snort.destIp || null,
                  destPort: normalizedLog.metadata.snort.destPort || null,
                }
              : null,
          }
    )
  );

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
  const metadata = sanitizeMetadata(item.metadata);
  const timestamp = normalizeTimestamp(item.timestamp);

  const snortPriority = toSafeNumber(metadata?.snort?.priority);
  const inferredLevel =
    snortPriority !== undefined && snortPriority <= 2 ? "warn" : "info";

  let normalized = {
    message: String(item.message || "").trim(),
    level: String(item.level || "").trim().toLowerCase() || inferredLevel,
    source: String(item.source || context.defaultSource || "agent").trim(),
    ip: String(item.ip || metadata?.snort?.srcIp || context.ip || "").trim(),
    userId: item.userId || undefined,
    endpoint: item.endpoint || metadata.endpoint || undefined,
    method: item.method || metadata.method || undefined,
    statusCode:
      item.statusCode !== undefined && item.statusCode !== null
        ? toSafeNumber(item.statusCode)
        : toSafeNumber(metadata.statusCode),
    eventType: item.eventType || metadata.eventType || undefined,
    metadata: {
      ...metadata,
      statusCode:
        item.statusCode !== undefined && item.statusCode !== null
          ? toSafeNumber(item.statusCode)
          : toSafeNumber(metadata.statusCode),
    },
    timestamp,
    _asset_id: context.assetId || item._asset_id || undefined,
    _org_id: context.orgId || item._org_id || undefined,
  };

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

  if (normalized.metadata?.snort) {
    normalized.metadata.snort = {
      ...normalized.metadata.snort,
      priority: toSafeNumber(normalized.metadata.snort.priority),
      generatorId: toSafeNumber(normalized.metadata.snort.generatorId),
      signatureId: toSafeNumber(normalized.metadata.snort.signatureId),
      revision: toSafeNumber(normalized.metadata.snort.revision),
      srcPort: toSafeNumber(normalized.metadata.snort.srcPort),
      destPort: toSafeNumber(normalized.metadata.snort.destPort),
    };
  }

  normalized.eventId = String(item.eventId || buildEventFingerprint(normalized));
  return normalized;
};

const emitLogsCreated = ({ orgId, logs, source, duplicateCount = 0, mode = "live" }) => {
  if (!logs.length) return;

  emitToOrganization(orgId, "logs:new", {
    type: "created",
    organizationId: orgId?.toString?.() || orgId || null,
    data: logs[0],
    items: logs.slice(0, 5),
    meta: {
      insertedCount: logs.length,
      duplicateCount,
      source,
      mode,
    },
  });

  emitToOrganization(orgId, "dashboard:update", {
    organizationId: orgId?.toString?.() || orgId || null,
    source,
    mode,
    insertedCount: logs.length,
    duplicateCount,
    lastLog: logs[0] || null,
    timestamp: new Date().toISOString(),
  });
};

const emitAlertsHint = ({ orgId, logs }) => {
  if (!logs.length) return;

  const possibleAlerts = logs.filter((log) => {
    const severityPriority = toSafeNumber(log?.metadata?.snort?.priority);
    const level = String(log?.level || "").toLowerCase();
    return (
      log?.source === "snort" ||
      !!log?.metadata?.snort ||
      level === "warn" ||
      level === "error" ||
      (severityPriority !== undefined && severityPriority <= 2)
    );
  });

  if (!possibleAlerts.length) return;

  emitToOrganization(orgId, "alerts:new", {
    organizationId: orgId?.toString?.() || orgId || null,
    count: possibleAlerts.length,
    items: possibleAlerts.slice(0, 5),
    timestamp: new Date().toISOString(),
  });
};

const runDetections = async (logs) => {
  for (const log of logs) {
    await evaluateLog(log);
  }

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

  emitLogsCreated({
    orgId,
    logs: stored,
    source,
    duplicateCount,
    mode,
  });

  emitAlertsHint({
    orgId,
    logs: stored,
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

const simulateTraffic = async (req, res) => {
  try {
    if (!config.allowSyntheticTraffic) {
      return res.status(403).json({
        message: "Synthetic traffic is disabled. Use the live Snort agent for real-time data.",
      });
    }

    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }

    const count = clampInt(req.query.count || "10", 10, 1, 200);
    const samples = generateTrafficBatch(count);

    const normalizedLogs = samples.map((sample) =>
      normalizeLogEntry(
        {
          message: `${sample.protocol} traffic sample on port ${sample.destinationPort}`,
          level:
            sample.severityHint === "Critical" || sample.severityHint === "High"
              ? "warn"
              : "info",
          source: "simulator",
          ip: sample.ip,
          endpoint: sample.endpoint,
          method: sample.method,
          statusCode: sample.statusCode,
          eventType: "request",
          metadata: {
            ...sample,
            demo: true,
          },
        },
        {
          orgId: req.orgId,
          defaultSource: "simulator",
        }
      )
    );

    const result = await persistLogs(normalizedLogs, {
      orgId: req.orgId,
      source: "simulator",
      mode: "demo",
    });

    return res.status(201).json({
      data: result.stored,
      meta: {
        insertedCount: result.insertedCount,
        duplicateCount: result.duplicateCount,
      },
    });
  } catch (error) {
    console.error("simulateTraffic error:", error);
    return res.status(500).json({ message: "Failed to simulate traffic" });
  }
};

module.exports = {
  listLogs,
  createLog,
  ingestLogs,
  uploadLogs,
  simulateTraffic,
};
