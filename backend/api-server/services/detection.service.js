const axios = require("axios");
const config = require("../config/env");
const { evaluateLog } = require("./detector.service");

const evaluateLogs = async (logs) => {
	const list = Array.isArray(logs) ? logs : [logs];
	for (const log of list) {
		await evaluateLog(log);
	}
};

const requestIdsScan = async (samples = 5) => {
	const response = await axios.get(`${config.idsEngineUrl}/scan`, {
		params: { samples },
		timeout: 5000
	});
	return Array.isArray(response.data) ? response.data : [];
};

module.exports = {
	evaluateLogs,
	requestIdsScan
};
