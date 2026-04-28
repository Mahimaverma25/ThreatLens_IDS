const parseTimestamp = (value) => {
  if (!value) return new Date().toISOString();

  const raw = String(value).trim();

  const snortMatch = raw.match(
    /^(?<month>\d{2})\/(?<day>\d{2})-(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})(?:\.(?<fraction>\d+))?$/
  );

  if (!snortMatch?.groups) {
    const parsed = new Date(raw);
    return Number.isNaN(parsed.getTime())
      ? new Date().toISOString()
      : parsed.toISOString();
  }

  const now = new Date();
  const fraction = (snortMatch.groups.fraction || "0").slice(0, 3).padEnd(3, "0");

  const parsed = new Date(
    now.getFullYear(),
    Number(snortMatch.groups.month) - 1,
    Number(snortMatch.groups.day),
    Number(snortMatch.groups.hour),
    Number(snortMatch.groups.minute),
    Number(snortMatch.groups.second),
    Number(fraction)
  );

  if (parsed.getTime() > now.getTime() + 24 * 60 * 60 * 1000) {
    parsed.setFullYear(parsed.getFullYear() - 1);
  }

  return parsed.toISOString();
};

const splitAddress = (value) => {
  if (!value) return { ip: "", port: null };

  const raw = String(value).trim();

  const ipv4Match = raw.match(
    /^(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?<port>\d+))?$/
  );

  if (ipv4Match?.groups) {
    return {
      ip: ipv4Match.groups.ip,
      port: ipv4Match.groups.port ? Number(ipv4Match.groups.port) : null,
    };
  }

  const bracketedIpv6Match = raw.match(/^\[(?<ip>.+)\](?::(?<port>\d+))?$/);

  if (bracketedIpv6Match?.groups) {
    return {
      ip: bracketedIpv6Match.groups.ip,
      port: bracketedIpv6Match.groups.port
        ? Number(bracketedIpv6Match.groups.port)
        : null,
    };
  }

  const parts = raw.split(":");

  if (parts.length > 2) {
    return { ip: raw, port: null };
  }

  return { ip: raw, port: null };
};

const normalizePriority = (priority) => {
  const value = Number(priority || 0);
  return Number.isFinite(value) && value > 0 ? value : 4;
};

const severityFromPriority = (priority) => {
  if (priority <= 1) return "critical";
  if (priority === 2) return "high";
  if (priority === 3) return "medium";
  return "low";
};

const levelFromPriority = (priority) => {
  if (priority <= 1) return "error";
  if (priority === 2) return "warn";
  return "info";
};

const buildSnortLog = ({
  timestamp,
  message,
  protocol,
  srcAddress,
  dstAddress,
  classification,
  priority,
  gid,
  sid,
  rev,
  raw,
}) => {
  const normalizedPriority = normalizePriority(priority);
  const source = splitAddress(srcAddress);
  const destination = splitAddress(dstAddress);

  return {
    timestamp: parseTimestamp(timestamp),
    source: "snort",
    eventType: "snort.alert",
    level: levelFromPriority(normalizedPriority),
    severity: severityFromPriority(normalizedPriority),
    message: message || "Snort Alert",

    ip: source.ip || destination.ip || "",
    srcIp: source.ip || "",
    srcPort: source.port,
    destIp: destination.ip || "",
    destPort: destination.port,
    protocol: protocol || "UNKNOWN",

    metadata: {
      parser: "snort-parser",
      raw,
      protocol: protocol || "UNKNOWN",
      port: destination.port,
      destinationPort: destination.port,
      snort: {
        generatorId: gid ? Number(gid) : null,
        signatureId: sid ? Number(sid) : null,
        revision: rev ? Number(rev) : null,
        classification: classification || "Unknown",
        priority: normalizedPriority,
        severity: severityFromPriority(normalizedPriority),
        message: message || "Snort Alert",
        srcIp: source.ip || "",
        srcPort: source.port,
        destIp: destination.ip || "",
        destPort: destination.port,
      },
    },
  };
};

const parseFastAlertLine = (line) => {
  const trimmed = String(line || "").trim();
  if (!trimmed) return null;

  const match = trimmed.match(
    /^(?<timestamp>\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[\*\*\]\s+\[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\]\s+(?<message>.+?)\s+\[\*\*\](?:\s+\[Classification:\s*(?<classification>[^\]]+)\])?(?:\s+\[Priority:\s*(?<priority>\d+)\])?\s+\{(?<protocol>[A-Za-z0-9_-]+)\}\s+(?<src>.+?)\s+->\s+(?<dst>.+)$/
  );

  if (!match?.groups) return null;

  return buildSnortLog({
    timestamp: match.groups.timestamp,
    gid: match.groups.gid,
    sid: match.groups.sid,
    rev: match.groups.rev,
    message: match.groups.message,
    classification: match.groups.classification,
    priority: match.groups.priority,
    protocol: match.groups.protocol,
    srcAddress: match.groups.src,
    dstAddress: match.groups.dst,
    raw: trimmed,
  });
};

const parseEveJsonLine = (line) => {
  const trimmed = String(line || "").trim();
  if (!trimmed) return null;

  let parsed;

  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }

  if (parsed.event_type !== "alert" || !parsed.alert) {
    return null;
  }

  return buildSnortLog({
    timestamp: parsed.timestamp,
    message: parsed.alert.signature || "Snort Alert",
    protocol: parsed.proto || parsed.app_proto || "UNKNOWN",
    srcAddress: parsed.src_port
      ? `${parsed.src_ip}:${parsed.src_port}`
      : parsed.src_ip,
    dstAddress: parsed.dest_port
      ? `${parsed.dest_ip}:${parsed.dest_port}`
      : parsed.dest_ip,
    classification: parsed.alert.category,
    priority: parsed.alert.severity,
    gid: parsed.alert.gid,
    sid: parsed.alert.signature_id,
    rev: parsed.alert.rev,
    raw: trimmed,
  });
};

module.exports = {
  parseFastAlertLine,
  parseEveJsonLine,
  parseTimestamp,
};