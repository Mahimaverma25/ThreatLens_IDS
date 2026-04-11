const ALERT_SEVERITY = {
	CRITICAL: "Critical",
	HIGH: "High",
	MEDIUM: "Medium",
	LOW: "Low"
};

const ALERT_STATUS = {
	NEW: "New",
	ACKNOWLEDGED: "Acknowledged",
	INVESTIGATING: "Investigating",
	RESOLVED: "Resolved",
	FALSE_POSITIVE: "False Positive"
};

const LOG_LEVEL = {
	INFO: "info",
	WARN: "warn",
	ERROR: "error"
};

module.exports = {
	ALERT_SEVERITY,
	ALERT_STATUS,
	LOG_LEVEL
};
