const Alert = require("../models/Alerts");
const Log = require("../models/Log");

const escapeCsvValue = (value) => {
  const stringValue = String(value ?? "");
  return `"${stringValue.replace(/"/g, "\"\"")}"`;
};

const buildCsv = (headers, rows) => {
  const content = [
    headers.join(","),
    ...rows.map((row) => row.map(escapeCsvValue).join(",")),
  ].join("\n");

  return `${content}\n`;
};

const getReportSummary = async (req, res) => {
  const filter = { _org_id: req.orgId };

  const [alerts, logs] = await Promise.all([
    Alert.find(filter).sort({ timestamp: -1 }).limit(200),
    Log.find(filter).sort({ timestamp: -1 }).limit(200),
  ]);

  return res.json({
    data: {
      alerts,
      logs,
      totals: {
        alerts: alerts.length,
        logs: logs.length,
        criticalAlerts: alerts.filter((alert) => alert.severity === "Critical").length,
        resolvedAlerts: alerts.filter((alert) => alert.status === "Resolved").length,
      },
    },
  });
};

const exportAlertsCsv = async (req, res) => {
  const filter = { _org_id: req.orgId };

  if (req.query.severity) {
    filter.severity = req.query.severity;
  }

  const alerts = await Alert.find(filter).sort({ timestamp: -1 }).limit(1000);
  const csv = buildCsv(
    ["type", "ip", "severity", "status", "confidence", "risk_score", "timestamp"],
    alerts.map((alert) => [
      alert.type,
      alert.ip,
      alert.severity,
      alert.status,
      alert.confidence,
      alert.risk_score,
      alert.timestamp,
    ])
  );

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="threatlens-alerts.csv"');
  return res.status(200).send(csv);
};

const exportLogsCsv = async (req, res) => {
  const filter = { _org_id: req.orgId };

  const logs = await Log.find(filter).sort({ timestamp: -1 }).limit(1000);
  const csv = buildCsv(
    ["message", "ip", "protocol", "bytes", "destination_port", "request_rate", "timestamp"],
    logs.map((log) => [
      log.message,
      log.ip,
      log.metadata?.protocol || "",
      log.metadata?.bytes || 0,
      log.metadata?.destinationPort || log.metadata?.port || "",
      log.metadata?.requestRate || 0,
      log.timestamp,
    ])
  );

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="threatlens-logs.csv"');
  return res.status(200).send(csv);
};

module.exports = {
  getReportSummary,
  exportAlertsCsv,
  exportLogsCsv,
};
