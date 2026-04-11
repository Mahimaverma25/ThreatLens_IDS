const RefreshToken = require("../models/RefreshToken");

const runCleanupJob = async () => {
	const result = await RefreshToken.deleteMany({
		expiresAt: { $lt: new Date() }
	});

	return {
		deletedCount: result.deletedCount || 0
	};
};

module.exports = {
	runCleanupJob
};
