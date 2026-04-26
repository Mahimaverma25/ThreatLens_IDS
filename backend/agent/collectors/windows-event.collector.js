const { execFile } = require("child_process");
const { promisify } = require("util");

const logger = require("../utils/logger");
const { normalizeEvent } = require("../utils/eventNormalizer");

const execFileAsync = promisify(execFile);

const WINDOWS_QUERIES = [
  {
    key: "security-auth",
    logName: "Security",
    ids: [4624, 4625, 4672, 4688],
    maxEvents: 40,
  },
  {
    key: "system-service",
    logName: "System",
    ids: [7045],
    maxEvents: 20,
  },
  {
    key: "powershell-scriptblock",
    logName: "Microsoft-Windows-PowerShell/Operational",
    ids: [4104],
    maxEvents: 20,
  },
];

const toArray = (value) => (Array.isArray(value) ? value : value ? [value] : []);
const trimText = (value) => String(value ?? "").trim();

const extractField = (message, fieldName) => {
  const pattern = new RegExp(`${fieldName}\\s*:\\s*(.+)`, "i");
  const match = String(message || "").match(pattern);
  return trimText(match?.[1] || "");
};

const cleanAccountName = (message) => {
  const matches = [...String(message || "").matchAll(/Account Name\s*:\s*(.+)/gi)]
    .map((match) => trimText(match[1]))
    .filter((value) => value && value !== "-" && !value.endsWith("$"));

  return matches[0] || "";
};

const buildBaseMetadata = (record, key) => ({
  windowsEvent: {
    query: key,
    recordId: Number(record.RecordId || 0) || null,
    eventId: Number(record.Id || 0) || null,
    providerName: trimText(record.ProviderName || ""),
    logName: trimText(record.LogName || ""),
  },
});

const buildAuthEvent = (record, success) => {
  const message = trimText(record.Message || "");
  const userName = cleanAccountName(message);
  const sourceIp =
    extractField(message, "Source Network Address") ||
    extractField(message, "Network Address");

  return normalizeEvent({
    timestamp: record.TimeCreated,
    source: "host",
    eventType: success ? "auth.login" : "auth.failure",
    message:
      record.Id === 4624
        ? "Windows successful logon observed"
        : "Windows failed logon observed",
    ip: sourceIp || undefined,
    metadata: {
      sensorType: "host",
      host: {
        userName: userName || null,
        loginSuccess: success,
        workstation: extractField(message, "Workstation Name") || null,
        logonType: extractField(message, "Logon Type") || null,
      },
      ...buildBaseMetadata(record, "security-auth"),
    },
  });
};

const buildPrivilegeEvent = (record) => {
  const message = trimText(record.Message || "");

  return normalizeEvent({
    timestamp: record.TimeCreated,
    source: "host",
    eventType: "privilege.escalation",
    message: "Special privileges assigned to a new logon session",
    metadata: {
      sensorType: "host",
      host: {
        userName: cleanAccountName(message) || null,
        elevated: true,
      },
      ...buildBaseMetadata(record, "security-auth"),
    },
  });
};

const buildProcessEvent = (record) => {
  const message = trimText(record.Message || "");
  const processName =
    extractField(message, "New Process Name") ||
    extractField(message, "Process Name");
  const commandLine = extractField(message, "Process Command Line");
  const parentProcess = extractField(message, "Creator Process Name");

  return normalizeEvent({
    timestamp: record.TimeCreated,
    source: "host",
    eventType: "process.start",
    message: processName
      ? `Windows process creation observed: ${processName}`
      : "Windows process creation observed",
    metadata: {
      sensorType: "host",
      host: {
        processName: processName || null,
        commandLine: commandLine || null,
        parentProcessName: parentProcess || null,
        userName: cleanAccountName(message) || null,
      },
      ...buildBaseMetadata(record, "security-auth"),
    },
  });
};

const buildServiceEvent = (record) => {
  const message = trimText(record.Message || "");

  return normalizeEvent({
    timestamp: record.TimeCreated,
    source: "host",
    eventType: "service.change",
    message: "Windows service installation observed",
    metadata: {
      sensorType: "host",
      host: {
        serviceName: extractField(message, "Service Name") || null,
        serviceFileName: extractField(message, "Service File Name") || null,
        serviceStartType: extractField(message, "Service Start Type") || null,
        userName: extractField(message, "Account Name") || null,
      },
      ...buildBaseMetadata(record, "system-service"),
    },
  });
};

const buildPowerShellEvent = (record) => {
  const message = trimText(record.Message || "");
  const scriptBlock =
    extractField(message, "Script Block Text") || message.slice(0, 1500);

  return normalizeEvent({
    timestamp: record.TimeCreated,
    source: "host",
    eventType: "process.start",
    message: "PowerShell script block execution observed",
    metadata: {
      sensorType: "host",
      host: {
        processName: "powershell.exe",
        commandLine: scriptBlock || null,
        userName: extractField(message, "UserId") || null,
      },
      ...buildBaseMetadata(record, "powershell-scriptblock"),
    },
  });
};

const recordToEvent = (record) => {
  const eventId = Number(record.Id || 0);

  if (eventId === 4624) return buildAuthEvent(record, true);
  if (eventId === 4625) return buildAuthEvent(record, false);
  if (eventId === 4672) return buildPrivilegeEvent(record);
  if (eventId === 4688) return buildProcessEvent(record);
  if (eventId === 7045) return buildServiceEvent(record);
  if (eventId === 4104) return buildPowerShellEvent(record);
  return null;
};

class WindowsEventCollector {
  constructor(options = {}) {
    this.lookbackMinutes = Number(options.lookbackMinutes || 5);
    this.lastRecordIds = {};
  }

  async queryWindowsEvents(definition) {
    const ids = definition.ids.join(",");
    const command = [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      `$ErrorActionPreference='Stop'; Get-WinEvent -FilterHashtable @{LogName='${definition.logName}'; Id=@(${ids}); StartTime=(Get-Date).AddMinutes(-${this.lookbackMinutes})} -MaxEvents ${definition.maxEvents} | Sort-Object RecordId | Select-Object Id,RecordId,TimeCreated,ProviderName,LogName,Message | ConvertTo-Json -Compress`,
    ];

    try {
      const { stdout } = await execFileAsync("powershell.exe", command, {
        timeout: 15000,
        windowsHide: true,
        maxBuffer: 4 * 1024 * 1024,
      });

      const payload = trimText(stdout);
      if (!payload) return [];
      return toArray(JSON.parse(payload));
    } catch (error) {
      const stderr = trimText(error.stderr || "");
      const details = stderr || error.message;

      if (
        details.includes("No events were found") ||
        details.includes("There is not an event log on the localhost")
      ) {
        return [];
      }

      logger.warn(
        `Windows event query failed for ${definition.logName}: ${details}`
      );
      return [];
    }
  }

  async collect() {
    if (process.platform !== "win32") {
      return [];
    }

    const collected = [];

    for (const definition of WINDOWS_QUERIES) {
      const records = await this.queryWindowsEvents(definition);
      const lastRecordId = Number(this.lastRecordIds[definition.key] || 0);

      records
        .filter((record) => Number(record.RecordId || 0) > lastRecordId)
        .forEach((record) => {
          const normalized = recordToEvent(record);
          if (normalized) {
            collected.push(normalized);
          }
          this.lastRecordIds[definition.key] = Math.max(
            Number(this.lastRecordIds[definition.key] || 0),
            Number(record.RecordId || 0)
          );
        });
    }

    return collected;
  }
}

module.exports = WindowsEventCollector;
