const mongoose = require("mongoose");
const Incident = require("../models/Incident");
const Alert = require("../models/Alert");

const STATUS_OPTIONS = ["Open", "Investigating", "Resolved", "False Positive"];
const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];

const getOrgId = (req) => req.user?._org_id || req.user?.orgId || req.orgId || null;

const normalizeStatus = (value) =>
  STATUS_OPTIONS.includes(value) ? value : "Open";

const normalizeSeverity = (value) => {
  if (!value) return "Medium";

  const normalized = String(value).toLowerCase();

  if (normalized === "critical") return "Critical";
  if (normalized === "high") return "High";
  if (normalized === "medium") return "Medium";
  if (normalized === "low") return "Low";

  return SEVERITY_OPTIONS.includes(value) ? value : "Medium";
};

const emitIncidentEvent = (req, eventName, incident) => {
  const io = req.app.get("io");

  if (io) {
    io.emit(eventName, {
      data: incident,
      timestamp: new Date().toISOString(),
    });

    io.emit("dashboard:update", {
      type: "incident",
      timestamp: new Date().toISOString(),
    });
  }
};

const buildIncidentQuery = (req) => {
  const query = {};
  const orgId = getOrgId(req);

  if (orgId) query._org_id = orgId;

  if (req.query.status) query.status = req.query.status;
  if (req.query.severity) query.severity = req.query.severity;

  if (req.query.search) {
    const searchRegex = new RegExp(req.query.search, "i");

    query.$or = [
      { title: searchRegex },
      { incidentId: searchRegex },
      { sourceIps: searchRegex },
      { status: searchRegex },
      { severity: searchRegex },
    ];
  }

  return query;
};

const populateIncident = (query) =>
  query
    .populate("owner", "name username email role")
    .populate("alertIds")
    .populate("notes.by", "name username email role");

exports.listIncidents = async (req, res) => {
  const query = buildIncidentQuery(req);

  const incidents = await populateIncident(
    Incident.find(query).sort({ lastSeen: -1, updatedAt: -1 }).limit(200)
  );

  return res.json({
    success: true,
    count: incidents.length,
    data: incidents,
  });
};

exports.getIncident = async (req, res) => {
  const query = { _id: req.params.id };
  const orgId = getOrgId(req);

  if (orgId) query._org_id = orgId;

  const incident = await populateIncident(Incident.findOne(query));

  if (!incident) {
    return res.status(404).json({
      success: false,
      message: "Incident not found",
    });
  }

  return res.json({
    success: true,
    data: incident,
  });
};

exports.createIncident = async (req, res) => {
  const orgId = getOrgId(req);

  const {
    title,
    severity,
    status,
    sourceIps,
    alertIds,
    owner,
    note,
  } = req.body;

  const incident = await Incident.create({
    _org_id: orgId || undefined,
    incidentId: `INC-${Date.now()}`,
    title: title || "Security Incident",
    severity: normalizeSeverity(severity),
    status: normalizeStatus(status),
    sourceIps: Array.isArray(sourceIps) ? sourceIps : [],
    alertIds: Array.isArray(alertIds) ? alertIds : [],
    owner: owner || req.user?._id || undefined,
    firstSeen: new Date(),
    lastSeen: new Date(),
    notes: note
      ? [
          {
            note,
            by: req.user?._id,
            timestamp: new Date(),
          },
        ]
      : [],
  });

  const populatedIncident = await populateIncident(
    Incident.findById(incident._id)
  );

  emitIncidentEvent(req, "incidents:new", populatedIncident);

  return res.status(201).json({
    success: true,
    message: "Incident created successfully",
    data: populatedIncident,
  });
};

exports.createIncidentFromAlert = async (req, res) => {
  const orgId = getOrgId(req);

  const alertQuery = { _id: req.params.alertId };
  if (orgId) alertQuery._org_id = orgId;

  const alert = await Alert.findOne(alertQuery);

  if (!alert) {
    return res.status(404).json({
      success: false,
      message: "Alert not found",
    });
  }

  const sourceIp =
    alert.sourceIp ||
    alert.srcIp ||
    alert.ip ||
    alert.metadata?.srcIp ||
    alert.metadata?.snort?.srcIp ||
    "Unknown";

  const incident = await Incident.create({
    _org_id: orgId || alert._org_id || undefined,
    incidentId: `INC-${Date.now()}`,
    title: alert.title || alert.message || alert.signature || "Security Incident",
    severity: normalizeSeverity(alert.severity),
    status: "Open",
    sourceIps: sourceIp && sourceIp !== "Unknown" ? [sourceIp] : [],
    alertIds: [alert._id],
    owner: req.user?._id,
    firstSeen: alert.timestamp || new Date(),
    lastSeen: new Date(),
    notes: [
      {
        note: "Incident created from alert.",
        by: req.user?._id,
        timestamp: new Date(),
      },
    ],
  });

  const populatedIncident = await populateIncident(
    Incident.findById(incident._id)
  );

  emitIncidentEvent(req, "incidents:new", populatedIncident);

  return res.status(201).json({
    success: true,
    message: "Incident created from alert successfully",
    data: populatedIncident,
  });
};

exports.updateIncident = async (req, res) => {
  const orgId = getOrgId(req);

  const query = { _id: req.params.id };
  if (orgId) query._org_id = orgId;

  const incident = await Incident.findOne(query);

  if (!incident) {
    return res.status(404).json({
      success: false,
      message: "Incident not found",
    });
  }

  const { status, note, owner } = req.body;

  if (status) incident.status = normalizeStatus(status);

  if (owner !== undefined) {
    incident.owner =
      owner && mongoose.Types.ObjectId.isValid(owner) ? owner : undefined;
  }

  if (note && String(note).trim()) {
    incident.notes.push({
      note: String(note).trim(),
      by: req.user?._id,
      timestamp: new Date(),
    });
  }

  incident.lastSeen = new Date();

  await incident.save();

  const updatedIncident = await populateIncident(
    Incident.findById(incident._id)
  );

  emitIncidentEvent(req, "incidents:update", updatedIncident);

  return res.json({
    success: true,
    message: "Incident updated successfully",
    data: updatedIncident,
  });
};