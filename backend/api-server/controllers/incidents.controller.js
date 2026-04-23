const Incident = require("../models/Incident");
const { syncOpenIncidentsForOrganization } = require("../services/incident.service");

const listIncidents = async (req, res) => {
  await syncOpenIncidentsForOrganization(req.orgId);

  const filters = { _org_id: req.orgId };
  if (req.query.status) {
    filters.status = req.query.status;
  }
  if (req.query.severity) {
    filters.severity = req.query.severity;
  }
  if (req.query.search) {
    filters.$or = [
      { title: { $regex: req.query.search, $options: "i" } },
      { attackType: { $regex: req.query.search, $options: "i" } },
      { sourceIps: { $elemMatch: { $regex: req.query.search, $options: "i" } } },
    ];
  }

  const incidents = await Incident.find(filters)
    .populate("alertIds", "type attackType severity status timestamp ip")
    .populate("owner", "email username role")
    .sort({ lastSeen: -1 });

  return res.json({
    data: incidents,
    total: incidents.length,
  });
};

const getIncident = async (req, res) => {
  const incident = await Incident.findOne({
    _id: req.params.id,
    _org_id: req.orgId,
  })
    .populate("alertIds")
    .populate("owner", "email username role")
    .populate("notes.by", "email username role");

  if (!incident) {
    return res.status(404).json({ message: "Incident not found" });
  }

  return res.json({ data: incident });
};

const updateIncident = async (req, res) => {
  const incident = await Incident.findOne({
    _id: req.params.id,
    _org_id: req.orgId,
  });

  if (!incident) {
    return res.status(404).json({ message: "Incident not found" });
  }

  const { status, owner, note, tags } = req.body || {};

  if (status) {
    incident.status = status;
    if (["Resolved", "False Positive"].includes(status)) {
      incident.resolvedAt = new Date();
    }
  }

  if (owner !== undefined) {
    incident.owner = owner || null;
  }

  if (Array.isArray(tags)) {
    incident.tags = tags.map((tag) => String(tag).trim()).filter(Boolean);
  }

  if (note) {
    incident.notes.push({
      note: String(note).trim(),
      by: req.user.sub,
    });
  }

  await incident.save();

  return res.json({ data: incident });
};

module.exports = {
  listIncidents,
  getIncident,
  updateIncident,
};
