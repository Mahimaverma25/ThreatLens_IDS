const { v4: uuidv4 } = require("uuid");

const Alert = require("../models/Alerts");
const Incident = require("../models/Incident");
const { emitToOrganization } = require("../socket");

const ACTIVE_INCIDENT_STATUSES = new Set(["Open", "Acknowledged", "Investigating", "Contained"]);
const SEVERITY_RANK = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const normalizeIp = (value) => String(value || "").trim();
const normalizeUserName = (value) => String(value || "").trim().toLowerCase();
const normalizeText = (value) => String(value || "").trim();

const incidentSocketPayload = (incident, type, meta = {}) => ({
  type,
  organizationId: incident._org_id?.toString?.() || incident._org_id || null,
  data: incident,
  meta,
});

const emitIncident = (eventName, incident, type, meta = {}) => {
  emitToOrganization(incident._org_id, eventName, incidentSocketPayload(incident, type, meta));
};

const buildSummary = (alert) => {
  const confidence = Math.round(Number(alert.confidence || 0.5) * 100);
  const risk = Number(alert.risk_score || 50);
  return `${alert.attackType || alert.type} from ${alert.ip || "unknown"} at ${confidence}% confidence and risk ${risk}.`;
};

const getAttackChainStep = (alert) => {
  const family = normalizeText(alert?.metadata?.family).toLowerCase();
  const attackType = normalizeText(alert?.attackType || alert?.type).toLowerCase();

  if (family.includes("port-scan") || attackType.includes("scan")) return "reconnaissance";
  if (family.includes("ssh-brute-force") || family.includes("authentication") || attackType.includes("brute")) {
    return "credential-access";
  }
  if (family.includes("process") || attackType.includes("process")) return "execution";
  if (family.includes("data-exfiltration") || attackType.includes("exfiltration")) return "exfiltration";
  if (family.includes("dns") || attackType.includes("dns")) return "command-and-control";
  return family || attackType || "general-threat";
};

const calculateIncidentSeverity = (incident, incomingAlert) => {
  const chainSteps = new Set([
    ...(Array.isArray(incident?.metadata?.attackChain) ? incident.metadata.attackChain : []),
    getAttackChainStep(incomingAlert),
  ]);

  if (
    chainSteps.has("reconnaissance") &&
    chainSteps.has("credential-access") &&
    chainSteps.has("execution")
  ) {
    return "Critical";
  }

  if (
    chainSteps.has("credential-access") &&
    (chainSteps.has("execution") || chainSteps.has("command-and-control") || chainSteps.has("exfiltration"))
  ) {
    return "Critical";
  }

  return mergeSeverity(incident?.severity, incomingAlert?.severity || "Medium");
};

const mergeSeverity = (current, incoming) =>
  (SEVERITY_RANK[incoming] || 0) > (SEVERITY_RANK[current] || 0) ? incoming : current;

const appendUnique = (target, value) => {
  if (!value) return target;
  const normalized = String(value).trim();
  if (!normalized || target.includes(normalized)) return target;
  return [...target, normalized];
};

const appendUniqueObjectId = (target, value) => {
  if (!value) return target;
  const normalized = value.toString();
  if (target.some((existing) => existing.toString() === normalized)) {
    return target;
  }
  return [...target, value];
};

const upsertIncidentFromAlert = async (alertDoc) => {
  if (!alertDoc?._org_id) {
    return null;
  }

  const attackType = String(alertDoc.attackType || alertDoc.type || "Threat Activity").trim();
  const ip = normalizeIp(alertDoc.ip);
  const destinationIp = normalizeIp(
    alertDoc?.metadata?.destinationIp || alertDoc?.metadata?.snort?.destIp
  );
  const userName = normalizeUserName(
    alertDoc?.metadata?.userName || alertDoc?.metadata?.host?.userName
  );
  const correlationStart = new Date(Date.now() - 2 * 60 * 60 * 1000);

  let incident = await Incident.findOne({
    _org_id: alertDoc._org_id,
    status: { $in: [...ACTIVE_INCIDENT_STATUSES] },
    lastSeen: { $gte: correlationStart },
    $or: [
      ...(ip ? [{ sourceIps: ip }] : []),
      ...(destinationIp ? [{ destinationIps: destinationIp }] : []),
      ...(userName ? [{ "metadata.userNames": userName }] : []),
      ...(alertDoc._asset_id ? [{ assetIds: alertDoc._asset_id }] : []),
      {
        attackType,
        source: alertDoc.source || "correlation-engine",
      },
    ],
  }).sort({ lastSeen: -1 });

  if (!incident) {
    incident = await Incident.create({
      _org_id: alertDoc._org_id,
      incidentId: `inc_${uuidv4().slice(0, 8)}`,
      title: attackType,
      attackType,
      severity: alertDoc.severity || "Medium",
      status: "Open",
      source: alertDoc.source || "correlation-engine",
      summary: buildSummary(alertDoc),
      sourceIps: ip ? [ip] : [],
      destinationIps: alertDoc.metadata?.destinationIp ? [alertDoc.metadata.destinationIp] : [],
      assetIds: alertDoc._asset_id ? [alertDoc._asset_id] : [],
      alertIds: [alertDoc._id],
      confidence: Number(alertDoc.confidence || 0.5),
      risk_score: Number(alertDoc.risk_score || 50),
      eventCount: 1,
      firstSeen: alertDoc.timestamp || new Date(),
      lastSeen: alertDoc.timestamp || new Date(),
      metadata: {
        sources: [alertDoc.source || "unknown"],
        userNames: userName ? [userName] : [],
        attackChain: [getAttackChainStep(alertDoc)],
      },
    });

    emitIncident("incidents:new", incident, "created");
  } else {
    incident.title =
      incident.title && incident.title !== attackType
        ? `${incident.title} / ${attackType}`
        : attackType;
    incident.attackType = incident.attackType || attackType;
    incident.severity = calculateIncidentSeverity(incident, alertDoc);
    incident.summary = buildSummary(alertDoc);
    incident.sourceIps = appendUnique(incident.sourceIps || [], ip);
    incident.destinationIps = appendUnique(
      incident.destinationIps || [],
      alertDoc.metadata?.destinationIp || alertDoc.metadata?.snort?.destIp
    );
    incident.assetIds = appendUniqueObjectId(incident.assetIds || [], alertDoc._asset_id);
    incident.alertIds = appendUniqueObjectId(incident.alertIds || [], alertDoc._id);
    incident.eventCount = incident.alertIds.length;
    incident.lastSeen = alertDoc.timestamp || new Date();
    incident.confidence = Number(
      ((Number(incident.confidence || 0.5) + Number(alertDoc.confidence || 0.5)) / 2).toFixed(4)
    );
    incident.risk_score = Math.round(
      (Number(incident.risk_score || 50) + Number(alertDoc.risk_score || 50)) / 2
    );
    incident.metadata = {
      ...(incident.metadata || {}),
      sources: appendUnique(incident.metadata?.sources || [], alertDoc.source || "unknown"),
      userNames: userName
        ? appendUnique(incident.metadata?.userNames || [], userName)
        : incident.metadata?.userNames || [],
      attackChain: appendUnique(
        incident.metadata?.attackChain || [],
        getAttackChainStep(alertDoc)
      ),
    };
    await incident.save();

    emitIncident("incidents:update", incident, "updated", { reason: "alert-correlated" });
  }

  if (!alertDoc._incident_id || alertDoc._incident_id.toString() !== incident._id.toString()) {
    alertDoc._incident_id = incident._id;
    await alertDoc.save();
  }

  return incident;
};

const syncOpenIncidentsForOrganization = async (orgId) => {
  const alerts = await Alert.find({
    _org_id: orgId,
    status: { $ne: "Resolved" },
  })
    .sort({ timestamp: -1 })
    .limit(250);

  for (const alert of alerts) {
    await upsertIncidentFromAlert(alert);
  }
};

module.exports = {
  upsertIncidentFromAlert,
  syncOpenIncidentsForOrganization,
  appendUnique,
  appendUniqueObjectId,
  mergeSeverity,
  buildSummary,
};
