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
  const sourceType = clampText(
    metadata.sourceType ||
      metadata.agentType ||
      context.sourceType ||
      (source === "snort" ? "nids" : "generic")
  ).toLowerCase();
  const category = inferEventCategory(eventType, source);

  const normalized = {
    message: clampText(item.message || metadata.message || `${eventType} event`),
    level: inferSeverityLevel(item, metadata),
    source,
    ip: clampText(
      item.ip ||
        metadata?.snort?.srcIp ||
        metadata?.network?.sourceIp ||
        metadata?.host?.sourceIp ||
        context.ip
    ),
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
        assetId: context.assetId?.toString?.() || item._asset_id?.toString?.() || null,
        organizationId: context.orgId?.toString?.() || item._org_id?.toString?.() || null,
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
