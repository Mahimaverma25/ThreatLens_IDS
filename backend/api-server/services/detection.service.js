const axios = require("axios");

const config = require("../config/env");
const Log = require("../models/Log");
const { createDetectionAlert } = require("./detector.service");

const IDS_TIMEOUT_MS = 5000;

// Expanded protocol codes for more signature types
const protocolCodes = {
  TCP: 1,
  UDP: 2,
  ICMP: 3,
  HTTP: 4,
  HTTPS: 5,
  SSH: 6,
  DNS: 7,
  FTP: 8,
  SMTP: 9,
  POP3: 10,
  IMAP: 11,
  TELNET: 12,
  RDP: 13,
  SMB: 14,
  // Add more as needed
};

const mapProtocol = (value) => protocolCodes[String(value || "").toUpperCase()] || 0;
// This allows detection and logging of more protocol/signature types
const isIdsSensorLog = (log) =>
  ["snort", "suricata"].includes(
    String(log?.metadata?.sensorType || log?.source || "")
      .trim()
      .toLowerCase()
  );

const buildSampleFromLog = (log) => {
  const snort = log.metadata?.snort || {};
  const protocol = log.metadata?.protocol || snort.protocol || log.metadata?.appProtocol || "";
  const destinationPort = Number(
    log.metadata?.destinationPort ??
      log.metadata?.port ??
      snort.destPort ??
      0
  );

  return {
    event_id: log.eventId || log._id?.toString?.(),
    source: log.source,
    event_type: log.eventType,
    message: log.message,
    ip: log.ip || snort.srcIp || "",
    destination_ip: snort.destIp || "",
    destination_port: destinationPort,
    protocol,
    protocol_code: mapProtocol(protocol),
    request_rate: Number(log.metadata?.requestRate || 0),
    packets: Number(log.metadata?.packets || 0),
    bytes: Number(log.metadata?.bytes || 0),
    failed_attempts: Number(log.metadata?.failedAttempts || 0),
    flow_count: Number(log.metadata?.flowCount || 0),
    unique_ports: Number(log.metadata?.uniquePorts || 0),
    dns_queries: Number(log.metadata?.dnsQueries || 0),
    smb_writes: Number(log.metadata?.smbWrites || log.metadata?.smb_writes || 0),
    duration: Number(log.metadata?.duration || 0),
    snort_priority: Number(snort.priority || 0),
    is_snort: isIdsSensorLog(log) ? 1 : 0,
    timestamp: log.timestamp ? new Date(log.timestamp).toISOString() : new Date().toISOString(),
    metadata: {
      classification: snort.classification || "",
      signature_id: snort.signatureId || null,
      generator_id: snort.generatorId || null,
    },
  };
};

const buildIdsHeaders = () => {
  if (!config.integrationApiKey) {
    return {};
  }

  return {
    "x-integration-api-key": config.integrationApiKey,
  };
};

const getIdsEngineHealth = async () => {
  if (!config.enableIdsAnalysis) {
    return {
      status: "disabled",
      message: "IDS engine analysis disabled",
      reachable: false,
      modelLoaded: null,
      algorithm: null,
      usingFallback: true,
    };
  }

  try {
    const response = await axios.get(`${config.idsEngineUrl}/health`, {
      timeout: 3000,
      headers: buildIdsHeaders(),
    });

    const data = response.data || {};
    const normalizedStatus =
      String(data.status || "").toLowerCase() === "ok" ? "online" : data.status || "online";
    const modelInfo = data.model && typeof data.model === "object" ? data.model : null;

    return {
      status: normalizedStatus,
      reachable: true,
      message: data.message || "IDS engine reachable",
      modelLoaded:
        modelInfo && modelInfo.loaded !== undefined ? Boolean(modelInfo.loaded) : null,
      algorithm: modelInfo?.algorithm || null,
      trainedAt: modelInfo?.trained_at || null,
      usingFallback:
        modelInfo && modelInfo.using_fallback !== undefined
          ? Boolean(modelInfo.using_fallback)
          : null,
      featureNames: Array.isArray(modelInfo?.feature_names) ? modelInfo.feature_names : [],
      rfModel: modelInfo?.rf_model || null,
      svmModel: modelInfo?.svm_model || null,
      legacyModel: modelInfo?.legacy_model || null,
      error: modelInfo?.error || null,
      details: data,
    };
  } catch (error) {
    return {
      status: "offline",
      reachable: false,
      message: error.message,
      modelLoaded: null,
      algorithm: null,
      usingFallback: null,
      error: error.response?.data?.message || null,
    };
  }
};

const applyIdsResults = async (logs, results = []) => {
  const resultsByEventId = new Map(
    results
      .filter((item) => item && item.event_id)
      .map((item) => [item.event_id, item])
  );

  const updates = [];
  const anomalyAlerts = [];

  logs.forEach((log) => {
    const eventId = log.eventId || log._id?.toString?.();
    const result = resultsByEventId.get(eventId);

    if (!result) {
      return;
    }

    updates.push({
      updateOne: {
        filter: { _id: log._id },
        update: {
          $set: {
            "metadata.idsEngine": {
              analyzed_at: new Date(),
              algorithm: result.analysis?.algorithm || null,
              score: result.analysis?.score ?? null,
              confidence: result.analysis?.confidence ?? null,
              threshold: result.analysis?.threshold ?? null,
              is_anomaly: Boolean(result.analysis?.is_anomaly),
              severity: result.analysis?.severity || null,
              using_fallback: Boolean(result.analysis?.using_fallback),
              reason: result.analysis?.reason || null,
              submodels: result.analysis?.submodels || null,
            },
          },
        },
      },
    });

    if (result.analysis?.is_anomaly) {
      anomalyAlerts.push(
        createDetectionAlert({
          log,
          attackType: isIdsSensorLog(log)
            ? "ML Anomalous IDS Activity"
            : "ML Anomalous Network Activity",
          type: isIdsSensorLog(log)
            ? "ML Anomalous IDS Activity"
            : "ML Anomalous Network Activity",
          severity: result.analysis?.severity || "Medium",
          confidence: result.analysis?.confidence,
          risk_score: result.analysis?.risk_score,
          source: "ids-engine-ml",
          metadata: {
            algorithm: result.analysis?.algorithm || null,
            reason: result.analysis?.reason || null,
            score: result.analysis?.score ?? null,
            threshold: result.analysis?.threshold ?? null,
            using_fallback: Boolean(result.analysis?.using_fallback),
            predictedClass:
              result.analysis?.submodels?.random_forest?.predicted_class || null,
          },
        })
      );
    }
  });

  if (updates.length > 0) {
    await Log.bulkWrite(updates, { ordered: false });
  }

  if (anomalyAlerts.length > 0) {
    await Promise.all(anomalyAlerts);
  }
};

const analyzeLogs = async (logs = []) => {
  if (!config.enableIdsAnalysis || logs.length === 0) {
    return { status: "skipped", analyzed: 0, results: [] };
  }

  const events = logs.map(buildSampleFromLog);

  try {
    const response = await axios.post(
      `${config.idsEngineUrl}/analyze`,
      { events },
      {
        timeout: IDS_TIMEOUT_MS,
        headers: {
          "Content-Type": "application/json",
          ...buildIdsHeaders(),
        },
      }
    );

    const payload = response.data || {};
    const results = Array.isArray(payload.results) ? payload.results : [];
    await applyIdsResults(logs, results);

    return {
      status: payload.status || "ok",
      analyzed: results.length,
      model: payload.model || null,
      results,
    };
  } catch (error) {
    return {
      status: "offline",
      analyzed: 0,
      results: [],
      error: error.message,
    };
  }
};

module.exports = {
  analyzeLogs,
  getIdsEngineHealth,
  buildSampleFromLog,
};
