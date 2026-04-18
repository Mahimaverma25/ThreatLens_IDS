const parseTimestamp = (value) => {
  if (!value) {
    return new Date().toISOString();
  }

  const match = value.match(
    /^(?<month>\d{2})\/(?<day>\d{2})-(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})(?:\.(?<fraction>\d+))?$/
  );

  if (!match?.groups) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
  }

  const now = new Date();
  const fraction = (match.groups.fraction || "0").slice(0, 3).padEnd(3, "0");
  const parsed = new Date(
    now.getFullYear(),
    Number(match.groups.month) - 1,
    Number(match.groups.day),
    Number(match.groups.hour),
    Number(match.groups.minute),
    Number(match.groups.second),
    Number(fraction)
  );

  if (parsed.getTime() > now.getTime() + 24 * 60 * 60 * 1000) {
    parsed.setFullYear(parsed.getFullYear() - 1);
  }

  return parsed.toISOString();
};

const splitAddress = (value) => {
  if (!value) {
    return { ip: "", port: null };
  }

  const ipv4Match = value.match(/^(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?<port>\d+))?$/);
  if (ipv4Match?.groups) {
    return {
      ip: ipv4Match.groups.ip,
      port: ipv4Match.groups.port ? Number(ipv4Match.groups.port) : null,
    };
  }

  const bracketedIpv6Match = value.match(/^\[(?<ip>.+)\](?::(?<port>\d+))?$/);
  if (bracketedIpv6Match?.groups) {
    return {
      ip: bracketedIpv6Match.groups.ip,
      port: bracketedIpv6Match.groups.port ? Number(bracketedIpv6Match.groups.port) : null,
    };
  }

  return { ip: value, port: null };
};

const normalizePriority = (priority) => {
  const value = Number(priority || 0);
  return Number.isFinite(value) && value > 0 ? value : 4;
};

const levelFromPriority = (priority) => {
  if (priority <= 1) {
    return "error";
  }

  if (priority === 2) {
    return "warn";
  }

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
    message,
    level: levelFromPriority(normalizedPriority),
    source: "snort",
    eventType: "snort.alert",
    ip: source.ip || destination.ip || "",
    timestamp: parseTimestamp(timestamp),
    metadata: {
      protocol: protocol || "UNKNOWN",
      destinationPort: destination.port,
      port: destination.port,
      snort: {
        generatorId: gid ? Number(gid) : null,
        signatureId: sid ? Number(sid) : null,
        revision: rev ? Number(rev) : null,
        message,
        classification: classification || "Unknown",
        priority: normalizedPriority,
        protocol: protocol || "UNKNOWN",
        srcIp: source.ip || "",
        srcPort: source.port,
        destIp: destination.ip || "",
        destPort: destination.port,
        raw,
      },
    },
  };
};

const parseFastAlertLine = (line) => {
  const trimmed = String(line || "").trim();
  if (!trimmed) {
    return null;
  }

  const match = trimmed.match(
    /^(?<timestamp>\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[\*\*\]\s+\[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\]\s+(?<message>.+?)\s+\[\*\*\](?:\s+\[Classification:\s*(?<classification>[^\]]+)\])?(?:\s+\[Priority:\s*(?<priority>\d+)\])?\s+\{(?<protocol>[A-Za-z0-9_-]+)\}\s+(?<src>.+?)\s+->\s+(?<dst>.+)$/
  );

  if (!match?.groups) {
    return null;
  }

  return buildSnortLog({
    ...match.groups,
    srcAddress: match.groups.src,
    dstAddress: match.groups.dst,
    raw: trimmed,
  });
};

const parseEveJsonLine = (line) => {
  const trimmed = String(line || "").trim();
  if (!trimmed) {
    return null;
  }

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
    protocol: parsed.proto,
    srcAddress: parsed.src_port ? `${parsed.src_ip}:${parsed.src_port}` : parsed.src_ip,
    dstAddress: parsed.dest_port ? `${parsed.dest_ip}:${parsed.dest_port}` : parsed.dest_ip,
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
};
