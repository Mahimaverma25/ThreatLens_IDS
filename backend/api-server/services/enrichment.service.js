const { analyzeLogs, getIdsEngineHealth, buildSampleFromLog } = require("./detection.service");
const { normalizeSecurityEvent, buildEventFingerprint } = require("./normalization.service");

module.exports = {
  analyzeLogs,
  getIdsEngineHealth,
  buildSampleFromLog,
  normalizeSecurityEvent,
  buildEventFingerprint,
};
