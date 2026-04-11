const randomIp = () => `192.168.1.${Math.floor(Math.random() * 254) + 1}`;

const protocols = ["TCP", "UDP", "HTTP", "HTTPS", "SSH"];
const tcpFlags = ["SYN", "ACK", "FIN", "RST", "PSH"];
const countries = ["US", "IN", "DE", "SG", "NL", "JP", "AU", "GB"];
const endpoints = [
  "/api/auth/login",
  "/api/logs",
  "/api/alerts",
  "/api/dashboard/stats",
  "/admin/users",
  "/reports/export"
];

const pick = (values) => values[Math.floor(Math.random() * values.length)];

const getSeverityHint = (sample) => {
  if (sample.requestRate > 150 || sample.failedAttempts >= 6) {
    return "Critical";
  }

  if (sample.packets > 280 || sample.bytes > 65000) {
    return "High";
  }

  if (sample.flowCount > 18 || sample.duration > 15) {
    return "Medium";
  }

  return "Low";
};

const generateTrafficSample = () => {
  const destinationPort = pick([22, 53, 80, 123, 443, 445, 8080]);
  const protocol =
    destinationPort === 22
      ? "SSH"
      : destinationPort === 443
        ? "HTTPS"
        : destinationPort === 80 || destinationPort === 8080
          ? "HTTP"
          : pick(protocols);

  const packets = Math.floor(Math.random() * 460) + 40;
  const bytes = packets * (Math.floor(Math.random() * 120) + 60);
  const duration = Number((Math.random() * 18 + 0.5).toFixed(2));
  const failedAttempts =
    destinationPort === 22 ? Math.floor(Math.random() * 9) : Math.floor(Math.random() * 4);
  const flowCount = Math.floor(Math.random() * 25) + 1;
  const requestRate = Math.floor(Math.random() * 220) + 5;
  const sourceCountry = pick(countries);
  const destinationCountry = pick(countries);

  const sample = {
    ip: randomIp(),
    packets,
    bytes,
    duration,
    protocol,
    port: destinationPort,
    destinationPort,
    failedAttempts,
    flags: protocol === "UDP" ? ["NONE"] : [pick(tcpFlags), pick(tcpFlags)],
    flowCount,
    requestRate,
    endpoint: pick(endpoints),
    method: pick(["GET", "POST", "PUT", "DELETE"]),
    statusCode: pick([200, 200, 200, 401, 403, 429, 500]),
    sourceCountry,
    destinationCountry,
    direction: Math.random() > 0.5 ? "Inbound" : "Outbound",
    severityHint: "Low"
  };

  sample.severityHint = getSeverityHint(sample);
  return sample;
};

const generateTrafficBatch = (count = 10) =>
  Array.from({ length: count }, () => generateTrafficSample());

module.exports = { generateTrafficSample, generateTrafficBatch };
