const Log = require("../models/Log");
const { parse } = require("csv-parse/sync");
const config = require("../config/env");
const { evaluateLog } = require("../services/detector.service");
const { generateTrafficBatch } = require("../services/traffic.service");
const { getIo } = require("../socket");

const listLogs = async (req, res) => {
	try {
		const limit = Math.min(Number.parseInt(req.query.limit || "50", 10), 200);
		const page = Math.max(Number.parseInt(req.query.page || "1", 10), 1);
		const skip = (page - 1) * limit;

		// CRITICAL: Always filter by organization to prevent cross-org data leakage
		const filters = { _org_id: req.orgId };
		if (req.query.level) {
			filters.level = req.query.level;
		}
		if (req.query.source) {
			filters.source = req.query.source;
		}
		if (req.query.ip) {
			filters.ip = req.query.ip;
		}
		if (req.query.search) {
			filters.$or = [
				{ message: { $regex: req.query.search, $options: "i" } },
				{ eventType: { $regex: req.query.search, $options: "i" } }
			];
		}

		const [logs, total] = await Promise.all([
			Log.find(filters).sort({ timestamp: -1 }).skip(skip).limit(limit),
			Log.countDocuments(filters)
		]);

		return res.json({
			data: logs,
			pagination: { total, page, limit }
		});
	} catch (error) {
		return res.status(500).json({ message: "Failed to fetch logs" });
	}
};

const createLog = async (req, res) => {
	try {
		const { message, level, source, metadata, eventType, endpoint, method, statusCode } = req.body;

		if (!message) {
			return res.status(400).json({ message: "Log message is required" });
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
			statusCode
		});

		await evaluateLog(log);
		try {
			const io = getIo();
			io.emit("logs:new", log);
		} catch (error) {
			// noop
		}

		return res.status(201).json({ data: log });
	} catch (error) {
		return res.status(500).json({ message: "Failed to create log" });
	}
};

const ingestLogs = async (req, res) => {
	try {
		if (!config.integrationApiKey) {
			return res.status(400).json({ message: "Integration key not configured" });
		}

		const apiKey = req.headers["x-api-key"];
		if (apiKey !== config.integrationApiKey) {
			return res.status(401).json({ message: "Invalid integration key" });
		}

		const payload = Array.isArray(req.body) ? req.body : [req.body];
		const stored = [];
		for (const item of payload) {
			if (!item.message) {
				continue;
			}
			const log = await Log.create({
				message: item.message,
				level: item.level || "info",
				source: item.source || "integration",
				ip: item.ip || req.ip,
				eventType: item.eventType,
				metadata: item.metadata || {}
			});
			await evaluateLog(log);
			stored.push(log);
		}
		return res.status(201).json({ data: stored });
	} catch (error) {
		return res.status(500).json({ message: "Failed to ingest logs" });
	}
};

const uploadLogs = async (req, res) => {
	try {
		if (!req.file) {
			return res.status(400).json({ message: "Upload file required" });
		}

		const content = req.file.buffer.toString("utf-8");
		let items = [];
		if (req.file.mimetype.includes("json") || req.file.originalname.endsWith(".json")) {
			const parsed = JSON.parse(content);
			items = Array.isArray(parsed) ? parsed : [parsed];
		} else {
			items = parse(content, { columns: true, skip_empty_lines: true });
		}

		const stored = [];
		for (const item of items) {
			if (!item.message) {
				continue;
			}
			const log = await Log.create({
				message: item.message,
				level: item.level || "info",
				source: item.source || "upload",
				ip: item.ip || req.ip,
				eventType: item.eventType,
				metadata: item.metadata || {}
			});
			await evaluateLog(log);
			stored.push(log);
		}

		return res.status(201).json({ data: stored });
	} catch (error) {
		return res.status(500).json({ message: "Failed to upload logs" });
	}
};

const simulateTraffic = async (req, res) => {
	try {
		const count = Math.min(Number.parseInt(req.query.count || "10", 10), 200);
		const samples = generateTrafficBatch(count);
		const stored = [];
		for (const sample of samples) {
			const log = await Log.create({
				message: `Traffic sample on port ${sample.port}`,
				level: "info",
				source: "simulator",
				ip: sample.ip,
				endpoint: sample.endpoint,
				eventType: "traffic",
				metadata: sample
			});
			await evaluateLog(log);
			stored.push(log);
		}
		return res.status(201).json({ data: stored });
	} catch (error) {
		return res.status(500).json({ message: "Failed to simulate traffic" });
	}
};

module.exports = { listLogs, createLog, ingestLogs, uploadLogs, simulateTraffic };
