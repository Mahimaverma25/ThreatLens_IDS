const Alert = require("../models/Alerts");
const Incident = require("../models/Incident");
const Log = require("../models/Log");
const ThreatIndicator = require("../models/ThreatIndicator");

const COUNTRY_NODES = [
  { country: "United States", code: "US", coordinates: [-98.5795, 39.8283] },
  { country: "Canada", code: "CA", coordinates: [-106.3468, 56.1304] },
  { country: "Brazil", code: "BR", coordinates: [-51.9253, -14.235] },
  { country: "United Kingdom", code: "GB", coordinates: [-3.436, 55.3781] },
  { country: "Germany", code: "DE", coordinates: [10.4515, 51.1657] },
  { country: "France", code: "FR", coordinates: [2.2137, 46.2276] },
  { country: "Nigeria", code: "NG", coordinates: [8.6753, 9.082] },
  { country: "South Africa", code: "ZA", coordinates: [22.9375, -30.5595] },
  { country: "India", code: "IN", coordinates: [78.9629, 20.5937] },
  { country: "China", code: "CN", coordinates: [104.1954, 35.8617] },
  { country: "Japan", code: "JP", coordinates: [138.2529, 36.2048] },
  { country: "Singapore", code: "SG", coordinates: [103.8198, 1.3521] },
  { country: "Australia", code: "AU", coordinates: [133.7751, -25.2744] },
  { country: "Russia", code: "RU", coordinates: [105.3188, 61.524] },
  { country: "United Arab Emirates", code: "AE", coordinates: [53.8478, 23.4241] },
  { country: "South Korea", code: "KR", coordinates: [127.7669, 35.9078] },
  { country: "Israel", code: "IL", coordinates: [34.8516, 31.0461] },
  { country: "Turkey", code: "TR", coordinates: [35.2433, 38.9637] },
  { country: "Ukraine", code: "UA", coordinates: [31.1656, 48.3794] },
  { country: "Saudi Arabia", code: "SA", coordinates: [45.0792, 23.8859] },
  { country: "Indonesia", code: "ID", coordinates: [113.9213, -0.7893] },
  { country: "Mexico", code: "MX", coordinates: [-102.5528, 23.6345] },
  { country: "Argentina", code: "AR", coordinates: [-63.6167, -38.4161] },
  { country: "Spain", code: "ES", coordinates: [-3.7492, 40.4637] },
  { country: "Italy", code: "IT", coordinates: [12.5674, 41.8719] },
  { country: "Poland", code: "PL", coordinates: [19.1451, 51.9194] },
];

const COUNTRY_BY_CODE = new Map(COUNTRY_NODES.map((node) => [node.code, node]));
const DEFAULT_TARGET = COUNTRY_BY_CODE.get("US");

const hashString = (value = "") =>
  String(value)
    .split("")
    .reduce((sum, char) => sum + char.charCodeAt(0), 0);

const inferCountryNode = (value, fallbackCode = "US") => {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return COUNTRY_BY_CODE.get(fallbackCode) || DEFAULT_TARGET;
  }

  const direct = COUNTRY_BY_CODE.get(normalized.toUpperCase());
  if (direct) {
    return direct;
  }

  const index = hashString(normalized) % COUNTRY_NODES.length;
  return COUNTRY_NODES[index];
};

const severityToBand = (severity) => {
  const normalized = String(severity || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  return "low";
};

const topEntries = (items, keySelector, valueSelector = () => 1, limit = 10) => {
  const counts = new Map();
  items.forEach((item) => {
    const key = keySelector(item);
    if (!key) return;
    counts.set(key, (counts.get(key) || 0) + valueSelector(item));
  });
  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, limit);
};

const buildThreatIntelSummary = async (orgId) => {
  const [alerts, logs, incidents, indicators] = await Promise.all([
    Alert.find({ _org_id: orgId }).sort({ timestamp: -1 }).limit(300),
    Log.find({ _org_id: orgId }).sort({ timestamp: -1 }).limit(400),
    Incident.find({ _org_id: orgId }).sort({ lastSeen: -1 }).limit(150),
    ThreatIndicator.find({ _org_id: orgId, status: "active" }).sort({ createdAt: -1 }).limit(100),
  ]);

  const suspiciousIps = topEntries(
    alerts,
    (alert) => alert.ip,
    (alert) => Number(alert.risk_score || 1),
    12
  ).map((entry) => {
    const matchingAlerts = alerts.filter((alert) => alert.ip === entry.name);
    return {
      ip: entry.name,
      alerts: matchingAlerts.length,
      avgRisk: Math.round(
        matchingAlerts.reduce((sum, alert) => sum + Number(alert.risk_score || 0), 0) /
          Math.max(matchingAlerts.length, 1)
      ),
      attackTypes: [...new Set(matchingAlerts.map((alert) => alert.attackType || alert.type))].slice(0, 4),
    };
  });

  const sourceCountries = topEntries(
    [...alerts, ...logs],
    (item) =>
      item?.metadata?.sourceCountry ||
      item?.metadata?.country ||
      inferCountryNode(item.ip || item?.metadata?.snort?.srcIp || "").country,
    () => 1,
    10
  ).map((entry) => ({
    country: entry.name,
    count: entry.value,
  }));

  const topFamilies = topEntries(
    incidents,
    (incident) => incident.attackType || incident.title,
    (incident) => Number(incident.eventCount || incident.alertIds?.length || 1),
    10
  );

  return {
    suspiciousIps,
    sourceCountries,
    topFamilies,
    indicators,
    totals: {
      alerts: alerts.length,
      logs: logs.length,
      incidents: incidents.length,
      indicators: indicators.length,
      uniqueIps: new Set(alerts.map((alert) => alert.ip).filter(Boolean)).size,
    },
  };
};

const buildThreatMapSummary = async (orgId) => {
  const [alerts, incidents, indicators] = await Promise.all([
    Alert.find({ _org_id: orgId }).sort({ timestamp: -1 }).limit(120),
    Incident.find({ _org_id: orgId }).sort({ lastSeen: -1 }).limit(80),
    ThreatIndicator.find({ _org_id: orgId, status: "active" }).sort({ createdAt: -1 }).limit(50),
  ]);

  const mappedAttacks = alerts.map((alert) => {
    const sourceIp = alert.ip || alert.metadata?.sourceIp || "unknown";
    const destinationIp = alert.metadata?.destinationIp || alert.metadata?.snort?.destIp || "";
    const source = inferCountryNode(alert.metadata?.sourceCountry || sourceIp);
    const target = inferCountryNode(alert.metadata?.destinationCountry || destinationIp, "US");

    const [sourceLng, sourceLat] = source.coordinates;
    const [targetLng, targetLat] = target.coordinates;

    return {
      id: alert._id.toString(),
      source: {
        ...source,
        latitude: sourceLat,
        longitude: sourceLng,
      },
      target: {
        ...target,
        latitude: targetLat,
        longitude: targetLng,
      },
      attackType: alert.attackType || alert.type || "Threat Activity",
      severity: severityToBand(alert.severity),
      timestamp: alert.timestamp,
      vector: alert.metadata?.family || alert.metadata?.category || alert.source || "security-event",
      riskScore: Number(alert.risk_score || 50),
      sensorType: alert.metadata?.sensorType || alert.source || "unknown",
      destinationIp,
      sourceIp,
    };
  });

  const latestIncident = incidents[0] || null;

  return {
    attacks: mappedAttacks,
    summary: {
      total: mappedAttacks.length,
      highSeverity: mappedAttacks.filter((attack) => attack.severity === "high").length,
      mediumSeverity: mappedAttacks.filter((attack) => attack.severity === "medium").length,
      lowSeverity: mappedAttacks.filter((attack) => attack.severity === "low").length,
      activeIndicators: indicators.length,
      sensorDistribution: topEntries(mappedAttacks, (attack) => attack.sensorType, () => 1, 6),
      headline: latestIncident
        ? `${latestIncident.attackType} affecting ${latestIncident.sourceIps?.[0] || "multiple assets"}`
        : "No active attacks in the feed.",
    },
  };
};

module.exports = {
  buildThreatIntelSummary,
  buildThreatMapSummary,
  inferCountryNode,
  severityToBand,
  topEntries,
};
