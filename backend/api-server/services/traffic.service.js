const randomIp = () => `192.168.1.${Math.floor(Math.random() * 254) + 1}`;

const generateTrafficSample = () => ({
  ip: randomIp(),
  packets: Math.floor(Math.random() * 500) + 10,
  port: [22, 80, 443, 8080][Math.floor(Math.random() * 4)],
  endpoint: ["/api/auth/login", "/api/logs", "/api/alerts", "/api/dashboard/stats"][
    Math.floor(Math.random() * 4)
  ]
});

const generateTrafficBatch = (count = 10) =>
  Array.from({ length: count }, () => generateTrafficSample());

module.exports = { generateTrafficSample, generateTrafficBatch };
