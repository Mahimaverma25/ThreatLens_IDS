const Alert = require("../models/Alerts");
const { updateAlert } = require("../services/alert.service");

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

module.exports = { listAlerts, getAlertById, updateAlertStatus };
