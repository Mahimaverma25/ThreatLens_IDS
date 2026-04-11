const Log = require("../models/Log");
const { evaluateLog } = require("../services/detector.service");

const runAlertCorrelationJob = async (limit = 200) => {
	const logs = await Log.find({ eventType: { $exists: true } })
		.sort({ timestamp: -1 })
		.limit(limit);

	for (const log of logs) {
		await evaluateLog(log);
	}

	return logs.length;
};

module.exports = {
	runAlertCorrelationJob
};
