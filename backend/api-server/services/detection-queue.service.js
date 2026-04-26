const Log = require("../models/Log");
const { analyzeLogs } = require("./detection.service");

const queue = [];
let processing = false;

const processNext = async () => {
  if (processing || queue.length === 0) {
    return;
  }

  processing = true;
  const job = queue.shift();

  try {
    const logs = await Log.find({
      _org_id: job.orgId,
      _id: { $in: job.logIds },
    }).sort({ timestamp: -1 });

    if (logs.length > 0) {
      await analyzeLogs(logs);
    }
  } catch (error) {
    job.onError?.(error);
  } finally {
    processing = false;
    setImmediate(() => {
      void processNext();
    });
  }
};

const enqueueDetectionJob = ({ orgId, logIds, onError }) => {
  if (!orgId || !Array.isArray(logIds) || logIds.length === 0) {
    return { queued: false, queueDepth: queue.length };
  }

  queue.push({
    orgId,
    logIds,
    onError,
  });

  setImmediate(() => {
    void processNext();
  });

  return {
    queued: true,
    queueDepth: queue.length + (processing ? 1 : 0),
  };
};

const getDetectionQueueState = () => ({
  queued: queue.length,
  processing,
});

module.exports = {
  enqueueDetectionJob,
  getDetectionQueueState,
};
