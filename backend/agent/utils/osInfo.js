const os = require("os");

const getPrimaryIpv4 = () => {
  const interfaces = os.networkInterfaces();

  for (const entries of Object.values(interfaces)) {
    for (const entry of entries || []) {
      if (entry && entry.family === "IPv4" && !entry.internal) {
        return entry.address;
      }
    }
  }

  return "127.0.0.1";
};

const getOsInfo = () => ({
  hostname: os.hostname(),
  platform: os.platform(),
  release: os.release(),
  arch: os.arch(),
  ip: getPrimaryIpv4(),
  uptimeSeconds: os.uptime(),
  totalMemoryBytes: os.totalmem(),
  freeMemoryBytes: os.freemem(),
  cpuCount: os.cpus()?.length || 0,
});

module.exports = {
  getOsInfo,
  getPrimaryIpv4,
};
