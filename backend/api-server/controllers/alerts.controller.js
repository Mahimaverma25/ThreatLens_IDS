const Alert = require("../models/Alerts");
const Log = require("../models/Log");
const config = require("../config/env");
const { createAlert, updateAlert } = require("../services/alert.service");
const { requestIdsScan } = require("../services/detection.service");

const severityToConfidence = {
	Critical: 0.95,
	High: 0.84,
	Medium: 0.66,
	Low: 0.44
};

const severityToRiskScore = {
	Critical: 94,
	High: 78,
	Medium: 59,
	Low: 36
};

const listAlerts = async (req, res) => {
	try {
		const limit = Math.min(Number.parseInt(req.query.limit || "50", 10), 200);
		const page = Math.max(Number.parseInt(req.query.page || "1", 10), 1);
		const skip = (page - 1) * limit;

		// CRITICAL: Include org_id filter
		const filters = { _org_id: req.orgId };
		
		if (req.query.status) {
			filters.status = req.query.status;
		}
		if (req.query.severity) {
			filters.severity = req.query.severity;
		}
		if (req.query.source) {
			filters.source = req.query.source;
		}
		if (req.query.ip) {
			filters.ip = req.query.ip;
		}
		if (req.query.search) {
			filters.$or = [
				{ type: { $regex: req.query.search, $options: "i" } },
				{ attackType: { $regex: req.query.search, $options: "i" } }
			];
		}

		const [alerts, total] = await Promise.all([
			Alert.find(filters).sort({ timestamp: -1 }).skip(skip).limit(limit),
			Alert.countDocuments(filters)
		]);

		return res.json({
			data: alerts,
			pagination: { total, page, limit }
		});
	} catch (error) {
		console.error("[Alerts List Error]", error);
		return res.status(500).json({ message: "Failed to fetch alerts" });
	}
};

const getAlertById = async (req, res) => {
	try {
		// CRITICAL: Include org_id filter to ensure user can only access their org's alerts
		const alert = await Alert.findOne({
			_id: req.params.id,
			_org_id: req.orgId
		}).populate("relatedLogs");

		if (!alert) {
			return res.status(404).json({ message: "Alert not found" });
		}
		return res.json({ data: alert });
	} catch (error) {
		console.error("[Alert Get Error]", error);
		return res.status(500).json({ message: "Failed to load alert" });
	}
};

const updateAlertStatus = async (req, res) => {
	try {
		const { status, note } = req.body;
		
		// CRITICAL: Include org_id filter
		const alert = await Alert.findOne({
			_id: req.params.id,
			_org_id: req.orgId
		});

		if (!alert) {
			return res.status(404).json({ message: "Alert not found" });
		}

		if (status) {
			alert.status = status;
			if (["Resolved", "False Positive"].includes(status)) {
				alert.resolvedAt = new Date();
			}
		}

		if (note) {
			alert.analystNotes.push({ note, by: req.user._id });
		}

		await alert.save();
		await updateAlert(alert);
		return res.json({ data: alert });
	} catch (error) {
		console.error("[Alert Update Error]", error);
		return res.status(500).json({ message: "Failed to update alert" });
	}
};

const scanAndStore = async (req, res) => {
	try {
		if (!config.allowSyntheticTraffic) {
			return res.status(403).json({
				message: "Synthetic IDS scans are disabled. Use the live Snort agent for real-time alerts."
			});
		}

		const alerts = await requestIdsScan(12);
		const stored = [];
		for (const alert of alerts) {
			// CRITICAL: Add _org_id to log and alert
			const log = await Log.create({
				_org_id: req.orgId,
				message: `IDS scan detected ${alert.type}`,
				level: "warn",
				source: "ids-engine",
				ip: alert.ip,
				eventType: "ids.alert",
				metadata: alert
			});

			const created = await createAlert({
				_org_id: req.orgId,
				attackType: alert.type,
				type: alert.type,
				ip: alert.ip,
				severity: alert.severity || "Medium",
				confidence: alert.confidence ?? severityToConfidence[alert.severity || "Medium"] ?? 0.5,
				risk_score: alert.risk_score ?? severityToRiskScore[alert.severity || "Medium"] ?? 50,
				relatedLogs: [log._id],
				source: "ids-engine"
			});

			stored.push(created);
		}

		return res.json({ data: stored });
	} catch (error) {
		console.error("[Scan Store Error]", error);
		return res.status(502).json({ message: "IDS engine unavailable" });
	}
};

module.exports = { listAlerts, getAlertById, updateAlertStatus, scanAndStore };
