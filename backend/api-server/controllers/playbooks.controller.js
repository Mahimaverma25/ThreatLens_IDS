const Alert = require("../models/Alerts");
const PlaybookExecution = require("../models/PlaybookExecution");
const { updateAlert } = require("../services/alert.service");

const PLAYBOOKS = [
  {
    id: "block-ip",
    name: "Block IP",
    note: "Contain malicious source at firewall or WAF edge.",
    status: "Investigating",
  },
  {
    id: "disable-user",
    name: "Disable User",
    note: "Suspend suspicious account activity pending review.",
    status: "Investigating",
  },
  {
    id: "quarantine-asset",
    name: "Quarantine Asset",
    note: "Isolate impacted host from production network.",
    status: "Investigating",
  },
  {
    id: "mark-false-positive",
    name: "Mark False Positive",
    note: "Close noisy detection after analyst validation.",
    status: "False Positive",
  },
];

const listPlaybooks = async (req, res) => {
  const executions = await PlaybookExecution.find({ _org_id: req.orgId })
    .populate("alert_id", "type attackType ip severity status")
    .populate("triggered_by", "email username role")
    .sort({ createdAt: -1 })
    .limit(100);

  return res.json({
    data: {
      playbooks: PLAYBOOKS,
      executions,
    },
  });
};

const executePlaybook = async (req, res) => {
  const { alertId, playbookId } = req.body || {};

  if (!alertId || !playbookId) {
    return res.status(400).json({ message: "alertId and playbookId are required" });
  }

  const alert = await Alert.findOne({
    _id: alertId,
    _org_id: req.orgId,
  });

  if (!alert) {
    return res.status(404).json({ message: "Alert not found" });
  }

  const playbook = PLAYBOOKS.find((item) => item.id === playbookId);
  if (!playbook) {
    return res.status(404).json({ message: "Playbook not found" });
  }

  alert.status = playbook.status;
  alert.analystNotes.push({
    note: `${playbook.name}: ${playbook.note}`,
    by: req.user?.sub || null,
  });
  if (["Resolved", "False Positive"].includes(playbook.status)) {
    alert.resolvedAt = new Date();
  }
  await alert.save();
  await updateAlert(alert, { reason: "playbook-executed", playbookId: playbook.id });

  const execution = await PlaybookExecution.create({
    _org_id: req.orgId,
    alert_id: alert._id,
    playbook_id: playbook.id,
    playbook_name: playbook.name,
    note: playbook.note,
    triggered_by: req.user?.sub || null,
    metadata: {
      alertType: alert.type || alert.attackType || null,
      ip: alert.ip || null,
      resultingStatus: playbook.status,
    },
  });

  return res.status(201).json({
    data: {
      execution,
      alert,
    },
  });
};

module.exports = {
  listPlaybooks,
  executePlaybook,
};
