const Log = require("../models/Log");

const buildLogFilters = ({ orgId, level, source, ip, search }) => {
	const filters = { _org_id: orgId };

	if (level) {
		filters.level = level;
	}
	if (source) {
		filters.source = source;
	}
	if (ip) {
		filters.ip = ip;
	}
	if (search) {
		filters.$or = [
			{ message: { $regex: search, $options: "i" } },
			{ eventType: { $regex: search, $options: "i" } }
		];
	}

	return filters;
};

const listLogs = async ({ orgId, page = 1, limit = 50, ...filters }) => {
	const safeLimit = Math.min(Math.max(Number(limit), 1), 200);
	const safePage = Math.max(Number(page), 1);
	const skip = (safePage - 1) * safeLimit;
	const query = buildLogFilters({ orgId, ...filters });

	const [data, total] = await Promise.all([
		Log.find(query).sort({ timestamp: -1 }).skip(skip).limit(safeLimit),
		Log.countDocuments(query)
	]);

	return {
		data,
		pagination: {
			total,
			page: safePage,
			limit: safeLimit
		}
	};
};

const createLog = (payload) => Log.create(payload);

module.exports = {
	listLogs,
	createLog
};
