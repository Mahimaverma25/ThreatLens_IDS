const { sha256 } = require("../utils/ingestSignature");

const clampText = (value, fallback = "") => String(value || fallback).trim();
const toSafeNumber = (value) => {
  if (value === null || value === undefined || value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

const normalizeTimestamp = (value) => {
  const parsed = new Date(value || Date.now());
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
};

const sanitizeMetadata = (metadata) =>
  metadata && typeof metadata === "object" && !Array.isArray(metadata) ? metadata : {};

const truncateTimestampToSecond = (timestamp) => {
  const value = new Date(timestamp || Date.now());
  value.setMilliseconds(0);
  return value.toISOString();
};

const inferEventCategory = (eventType, source) => {
  const normalizedType = clampText(eventType).toLowerCase();
  const normalizedSource = clampText(source).toLowerCase();

  if (normalizedSource === "snort" || normalizedType.startsWith("snort.")) return "network";
  if (
    normalizedType.startsWith("auth.") ||
    normalizedType.startsWith("process.") ||
    normalizedType.startsWith("file.") ||
    normalizedType.startsWith("service.") ||
    normalizedType.startsWith("startup.") ||
    normalizedType.startsWith("privilege.")
  ) {
    return "host";
  }
  if (normalizedType.startsWith("agent.")) return "agent";
  return "application";
};

const inferSeverityLevel = (item, metadata) => {
  const explicit = clampText(item.level).toLowerCase();
  if (explicit) return explicit;

  const snortPriority = toSafeNumber(metadata?.snort?.priority);
  if (snortPriority !== undefined && snortPriority <= 1) return "error";
  if (snortPriority !== undefined && snortPriority <= 2) return "warn";

  if (metadata?.host?.severity) {
    const hostSeverity = clampText(metadata.host.severity).toLowerCase();
    if (["critical", "high"].includes(hostSeverity)) return "warn";
  }

  return "info";
};

const inferSensorType = ({ source, metadata, eventType }) => {
  const explicit = clampText(
    metadata?.sensorType ||
      metadata?.sourceType ||
      metadata?.agentType
  ).toLowerCase();

  if (explicit) {
    if (["snort", "suricata", "nids", "network"].includes(explicit)) return "nids";
    if (["host", "hids", "endpoint"].includes(explicit)) return "hids";
    if (["hybrid"].includes(explicit)) return "hybrid";
  }

  const normalizedSource = clampText(source).toLowerCase();
  const normalizedEventType = clampText(eventType).toLowerCase();

  if (["snort", "suricata"].includes(normalizedSource) || normalizedEventType.startsWith("snort.")) {
    return "nids";
  }

  if (
    ["host", "agent"].includes(normalizedSource) ||
    normalizedEventType.startsWith("auth.") ||
    normalizedEventType.startsWith("process.") ||
    normalizedEventType.startsWith("file.") ||
    normalizedEventType.startsWith("service.") ||
    normalizedEventType.startsWith("startup.") ||
    normalizedEventType.startsWith("privilege.")
  ) {
    return "hids";
  }

  if (normalizedSource.includes("ids")) {
    return "hybrid";
  }

  return "generic";
};

const normalizeSeverityLabel = (value, metadata = {}) => {
  const explicit = clampText(value || metadata?.severity || metadata?.host?.severity).toLowerCase();

  if (["critical", "high", "medium", "low", "info"].includes(explicit)) {
    return explicit;
  }

  const snortPriority = toSafeNumber(metadata?.snort?.priority);
  if (snortPriority !== undefined) {
    if (snortPriority <= 1) return "critical";
    if (snortPriority === 2) return "high";
    if (snortPriority === 3) return "medium";
    return "low";
  }

  const requestRate = toSafeNumber(metadata?.requestRate || metadata?.network?.requestRate);
  const failedAttempts = toSafeNumber(metadata?.failedAttempts || metadata?.host?.failedAttempts);

  if ((requestRate || 0) >= 200 || (failedAttempts || 0) >= 10) return "high";
  return "info";
};

const extractProtocol = (item, metadata) =>
  clampText(
    metadata?.protocol ||
      metadata?.appProtocol ||
      metadata?.snort?.protocol ||
      metadata?.network?.protocol ||
      item.protocol
  );

const extractSrcIp = (item, metadata, context) =>
  clampText(
    item.ip ||
      item.srcIp ||
      item.sourceIp ||
      metadata?.snort?.srcIp ||
      metadata?.network?.sourceIp ||
      metadata?.host?.sourceIp ||
      metadata?.sourceIp ||
      context.ip
  );

const extractDestIp = (item, metadata) =>
  clampText(
    item.destIp ||
      item.destinationIp ||
      metadata?.snort?.destIp ||
      metadata?.network?.destinationIp ||
      metadata?.destinationIp
  );

const extractPort = (item, metadata) =>
  toSafeNumber(
    item.port ??
      item.destPort ??
      item.destinationPort ??
      metadata?.destinationPort ??
      metadata?.port ??
      metadata?.network?.destinationPort ??
      metadata?.network?.port ??
      metadata?.snort?.destPort
  );

const extractAssetIdentity = (item, metadata, context) =>
  clampText(
    context.assetIdentity ||
      context.asset_id ||
      context.assetId ||
      metadata?.assetId ||
      metadata?.asset_id ||
      metadata?.normalized?.assetId ||
      item.assetId ||
      item.asset_id
  );

const extractUserName = (item, metadata) =>
  clampText(
    item.userName ||
      metadata?.host?.userName ||
      metadata?.userName ||
      metadata?.username ||
      metadata?.user
  );

const buildEventFingerprint = (normalizedLog) =>
  sha256(
    JSON.stringify({
      assetId: normalizedLog._asset_id?.toString?.() || normalizedLog._asset_id || null,
      source: normalizedLog.source,
      sourceType: normalizedLog.metadata?.normalized?.sourceType || null,
      eventType: normalizedLog.eventType || null,
      message: normalizedLog.message,
      ip: normalizedLog.ip || null,
      endpoint: normalizedLog.endpoint || null,
      method: normalizedLog.method || null,
      statusCode: normalizedLog.statusCode || null,
      timestamp: truncateTimestampToSecond(normalizedLog.timestamp),
      destinationPort:
        normalizedLog.metadata?.destinationPort ??
        normalizedLog.metadata?.port ??
        normalizedLog.metadata?.snort?.destPort ??
        normalizedLog.metadata?.network?.destinationPort ??
        null,
      protocol:
        normalizedLog.metadata?.protocol ||
        normalizedLog.metadata?.appProtocol ||
        normalizedLog.metadata?.snort?.protocol ||
        normalizedLog.metadata?.network?.protocol ||
        null,
      processName: normalizedLog.metadata?.host?.processName || null,
      filePath: normalizedLog.metadata?.host?.filePath || null,
      userName: normalizedLog.metadata?.host?.userName || null,
      snort: normalizedLog.metadata?.snort
        ? {
            generatorId: normalizedLog.metadata.snort.generatorId || null,
            signatureId: normalizedLog.metadata.snort.signatureId || null,
            revision: normalizedLog.metadata.snort.revision || null,
            classification: normalizedLog.metadata.snort.classification || null,
            priority: normalizedLog.metadata.snort.priority || null,
            srcIp: normalizedLog.metadata.snort.srcIp || null,
            srcPort: normalizedLog.metadata.snort.srcPort || null,
            destIp: normalizedLog.metadata.snort.destIp || null,
            destPort: normalizedLog.metadata.snort.destPort || null,
          }
        : null,
    })
  );

const normalizeSecurityEvent = (item, context = {}) => {
  const metadata = sanitizeMetadata(item.metadata);
  const timestamp = normalizeTimestamp(item.timestamp);
  const source = clampText(item.source || context.defaultSource || "agent");
  const eventType = clampText(item.eventType || metadata.eventType || "event");
  const sourceType = inferSensorType({ source, metadata, eventType });
  const category = inferEventCategory(eventType, source);
  const protocol = extractProtocol(item, metadata);
  const srcIp = extractSrcIp(item, metadata, context);
  const destIp = extractDestIp(item, metadata);
  const port = extractPort(item, metadata);
  const severity = normalizeSeverityLabel(item.level, metadata);
  const assetId = extractAssetIdentity(item, metadata, context);
  const userName = extractUserName(item, metadata);
  const hostname = clampText(metadata?.hostname || metadata?.host?.hostname || metadata?.host || context.hostname);

  const normalized = {
    message: clampText(item.message || metadata.message || `${eventType} event`),
    level: inferSeverityLevel(item, metadata),
    source,
    ip: srcIp,
    userId: item.userId || undefined,
    endpoint: item.endpoint || metadata.endpoint || undefined,
    method: item.method || metadata.method || undefined,
    statusCode:
      item.statusCode !== undefined && item.statusCode !== null
        ? toSafeNumber(item.statusCode)
        : toSafeNumber(metadata.statusCode),
    eventType,
    metadata: {
      ...metadata,
      destinationPort:
        toSafeNumber(metadata.destinationPort) ??
        toSafeNumber(metadata.port) ??
        toSafeNumber(metadata?.network?.destinationPort) ??
        undefined,
      port:
        toSafeNumber(metadata.port) ??
        toSafeNumber(metadata.destinationPort) ??
        toSafeNumber(metadata?.network?.destinationPort) ??
        undefined,
      normalized: {
        schemaVersion: "2026-04-hybrid-1",
        category,
        sourceType,
        timestamp: timestamp.toISOString(),
        source,
        sensorType: sourceType,
        srcIp: srcIp || null,
        destIp: destIp || null,
        port: port ?? null,
        protocol: protocol || null,
        eventType,
        severity,
        message: clampText(item.message || metadata.message || `${eventType} event`),
        assetId: assetId || context.assetId?.toString?.() || item._asset_id?.toString?.() || null,
        organizationId: context.orgId?.toString?.() || item._org_id?.toString?.() || null,
        userName: userName || null,
        hostname: hostname || null,
      },
    },
    timestamp,
    _asset_id: context.assetId || item._asset_id || undefined,
    _org_id: context.orgId || item._org_id || undefined,
  };

  if (normalized.metadata?.snort) {
    normalized.metadata.snort = {
      ...normalized.metadata.snort,
      priority: toSafeNumber(normalized.metadata.snort.priority),
      generatorId: toSafeNumber(normalized.metadata.snort.generatorId),
      signatureId: toSafeNumber(normalized.metadata.snort.signatureId),
      revision: toSafeNumber(normalized.metadata.snort.revision),
      srcPort: toSafeNumber(normalized.metadata.snort.srcPort),
      destPort: toSafeNumber(normalized.metadata.snort.destPort),
    };
  }

  if (normalized.metadata?.network) {
    normalized.metadata.network = {
      ...normalized.metadata.network,
      protocol: protocol || normalized.metadata.network.protocol || undefined,
      sourceIp: srcIp || normalized.metadata.network.sourceIp || undefined,
      destinationIp: destIp || normalized.metadata.network.destinationIp || undefined,
      destinationPort: toSafeNumber(normalized.metadata.network.destinationPort),
      sourcePort: toSafeNumber(normalized.metadata.network.sourcePort),
      packets: toSafeNumber(normalized.metadata.network.packets),
      bytes: toSafeNumber(normalized.metadata.network.bytes),
      flowCount: toSafeNumber(normalized.metadata.network.flowCount),
    };
  }

  if (normalized.metadata?.host) {
    normalized.metadata.host = {
      ...normalized.metadata.host,
      userName: userName || normalized.metadata.host.userName || undefined,
      hostname: hostname || normalized.metadata.host.hostname || undefined,
      pid: toSafeNumber(normalized.metadata.host.pid),
      parentPid: toSafeNumber(normalized.metadata.host.parentPid),
      loginSuccess:
        normalized.metadata.host.loginSuccess === undefined
          ? undefined
          : Boolean(normalized.metadata.host.loginSuccess),
      elevated:
        normalized.metadata.host.elevated === undefined
          ? undefined
          : Boolean(normalized.metadata.host.elevated),
    };
  }

  normalized.metadata.sensorType = normalized.metadata.sensorType || sourceType;
  normalized.metadata.protocol = protocol || normalized.metadata.protocol || undefined;
  normalized.metadata.sourceIp = srcIp || normalized.metadata.sourceIp || undefined;
  normalized.metadata.destinationIp = destIp || normalized.metadata.destinationIp || undefined;
  normalized.metadata.destinationPort = port ?? normalized.metadata.destinationPort;
  normalized.metadata.port = port ?? normalized.metadata.port;
  normalized.metadata.userName = userName || normalized.metadata.userName || undefined;
  normalized.metadata.hostname = hostname || normalized.metadata.hostname || undefined;
  normalized.metadata.severity = severity || normalized.metadata.severity || undefined;

  normalized.eventId = String(item.eventId || buildEventFingerprint(normalized));
  return normalized;
};

module.exports = {
  normalizeSecurityEvent,
  buildEventFingerprint,
  sanitizeMetadata,
  normalizeTimestamp,
  toSafeNumber,
};
