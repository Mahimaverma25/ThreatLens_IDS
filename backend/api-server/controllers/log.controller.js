const Log = require("../models/Log");
const { parse } = require("csv-parse/sync");
const { evaluateLog } = require("../services/detector.service");
const { generateTrafficBatch } = require("../services/traffic.service");
const { getIo } = require("../socket");

/* ================= LIST LOGS ================= */

const listLogs = async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || "50"), 200);
    const page = Math.max(parseInt(req.query.page || "1"), 1);
    const skip = (page - 1) * limit;

    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }

    const filters = { _org_id: req.orgId };

    if (req.query.level) filters.level = req.query.level;
    if (req.query.source) filters.source = req.query.source;
    if (req.query.ip) filters.ip = req.query.ip;

    if (req.query.search) {
      filters.$or = [
        { message: { $regex: req.query.search, $options: "i" } },
        { eventType: { $regex: req.query.search, $options: "i" } },
      ];
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
    console.error("❌ listLogs error:", error);
    return res.status(500).json({ message: "Failed to fetch logs" });
  }
};

/* ================= CREATE LOG ================= */

const createLog = async (req, res) => {
  try {
    const {
      message,
      level,
      source,
      metadata,
      eventType,
      endpoint,
      method,
      statusCode,
    } = req.body;

    if (!message) {
      return res.status(400).json({ message: "Log message is required" });
    }

    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }

    const log = await Log.create({
      message,
      level,
      source,
      metadata,
      ip: req.ip,
      userId: req.user?.sub,
      _org_id: req.orgId,
      eventType,
      endpoint,
      method,
      statusCode,
    });

    await evaluateLog(log);

    // real time emit does here
    try {
      const io = getIo();
      io.emit("logs:new", log);
    } catch (e) {}

    return res.status(201).json({ data: log });
  } catch (error) {
    console.error("❌ createLog error:", error);
    return res.status(500).json({ message: "Failed to create log" });
  }
};

/* ================= INGEST LOGS ================= */

const ingestLogs = async (req, res) => {
  console.log("🔥 HIT /api/logs/ingest");

  try {
    // ✅ org already validated by middleware
    if (!req.orgId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // ✅ FIX 1: get logs from request
    const logsArray = req.body.logs;

    if (!logsArray || !Array.isArray(logsArray)) {
      return res.status(400).json({ message: "Logs array required" });
    }

    console.log(`📦 Incoming logs count: ${logsArray.length}`);

    // ✅ Format logs properly
    const formattedLogs = logsArray
      .filter((item) => item && item.message)
      .map((item) => ({
        message: item.message,
        level: item.level || "info",
        source: item.source || "agent",
        ip: item.ip || req.ip,
        eventType: item.eventType,
        metadata: item.metadata || {},
        _asset_id: req.assetId,
        _org_id: req.orgId,
        timestamp: item.timestamp || new Date(),
      }));

    if (formattedLogs.length === 0) {
      return res.status(400).json({ message: "No valid logs to insert" });
    }

    // 🚀 Bulk insert (fast)
    const stored = await Log.insertMany(formattedLogs);

    // 🔥 IMPORTANT: run detection
    for (const log of stored) {
      await evaluateLog(log);
    }

    // 🔥 Real-time emit
    try {
      const io = getIo();
      io.emit("logs:new", {
        count: stored.length,
        latestLog: stored[stored.length - 1],
      });
    } catch (e) {}

    console.log(`✅ Stored logs: ${stored.length}`);

    return res.status(201).json({
      success: true,
      count: stored.length,
    });
  } catch (error) {
    console.error("❌ ingestLogs error:", error);
    return res.status(500).json({ message: "Failed to ingest logs" });
  }
};

/* ================= UPLOAD LOGS ================= */

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
      if (
        req.file.mimetype.includes("json") ||
        req.file.originalname.endsWith(".json")
      ) {
        const parsed = JSON.parse(content);
        items = Array.isArray(parsed) ? parsed : [parsed];
      } else {
        items = parse(content, { columns: true, skip_empty_lines: true });
      }
    } catch (parseError) {
      return res.status(400).json({ message: "Invalid file format" });
    }

    const formattedLogs = items
      .filter((item) => item && item.message)
      .map((item) => ({
        message: item.message,
        level: item.level || "info",
        source: item.source || "upload",
        ip: item.ip || req.ip,
        eventType: item.eventType,
        metadata: item.metadata || {},
        _org_id: req.orgId,
      }));

    const stored = await Log.insertMany(formattedLogs);

    for (const log of stored) {
      await evaluateLog(log);
    }

    try {
      const io = getIo();
      io.emit("logs:new", {
        count: stored.length,
        latestLog: stored[stored.length - 1],
      });
    } catch (e) {}

    return res.status(201).json({ data: stored });
  } catch (error) {
    console.error("❌ uploadLogs error:", error);
    return res.status(500).json({ message: "Failed to upload logs" });
  }
};

/* ================= SIMULATE TRAFFIC ================= */

const simulateTraffic = async (req, res) => {
  try {
    if (!req.orgId) {
      return res.status(400).json({ message: "Organization not found" });
    }

    const count = Math.min(parseInt(req.query.count || "10"), 200);
    const samples = generateTrafficBatch(count);

    const formattedLogs = samples.map((sample) => ({
      message: `Traffic sample on port ${sample.port}`,
      level: "info",
      source: "simulator",
      ip: sample.ip,
      endpoint: sample.endpoint,
      eventType: "traffic",
      metadata: sample,
      _org_id: req.orgId,
    }));

    const stored = await Log.insertMany(formattedLogs);

    for (const log of stored) {
      await evaluateLog(log);
    }

    try {
      const io = getIo();
      io.emit("logs:new", {
        count: stored.length,
        latestLog: stored[stored.length - 1],
      });
    } catch (e) {}

    return res.status(201).json({ data: stored });
  } catch (error) {
    console.error("❌ simulateTraffic error:", error);
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