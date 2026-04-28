import fs from "fs";
import path from "path";
import readline from "readline";

import config from "../config.js";
import logger from "../utils/logger.js";

const SNORT_FAST_REGEX =
  /(?<timestamp>\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\]\s+(?<message>.*?)\s+\[\*\*\]\s+\[Priority:\s*(?<priority>\d+)\]\s+\{(?<protocol>\w+)\}\s+(?<src_ip>[\d.:a-fA-F]+)(?::(?<src_port>\d+))?\s+->\s+(?<dest_ip>[\d.:a-fA-F]+)(?::(?<dest_port>\d+))?/;

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function parseSnortTimestamp(value) {
  if (!value) return new Date().toISOString();

  const year = new Date().getFullYear();
  const [monthDay, timePart] = value.split("-");
  const [month, day] = monthDay.split("/");

  return new Date(`${year}-${month}-${day}T${timePart}Z`).toISOString();
}

export function parseSnortFastLine(line) {
  const cleanLine = String(line || "").trim();
  if (!cleanLine) return null;

  const match = cleanLine.match(SNORT_FAST_REGEX);
  if (!match?.groups) {
    return null;
  }

  const g = match.groups;

  return {
    event_id: `snort-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    timestamp: parseSnortTimestamp(g.timestamp),

    source: "snort",
    event_type: "network_intrusion",

    src_ip: g.src_ip,
    dest_ip: g.dest_ip,
    src_port: safeNumber(g.src_port),
    dest_port: safeNumber(g.dest_port),
    port: safeNumber(g.dest_port),

    protocol: String(g.protocol || "UNKNOWN").toUpperCase(),

    attack_type: g.message,
    signature_id: safeNumber(g.sid),
    gid: safeNumber(g.gid),
    revision: safeNumber(g.rev),

    priority: safeNumber(g.priority),
    snort_priority: safeNumber(g.priority),
    is_snort: 1,

    packets: 1,
    bytes: 0,
    request_rate: 0,
    failed_attempts: 0,
    flow_count: 1,
    unique_ports: 1,
    dns_queries: String(g.protocol || "").toUpperCase() === "UDP" && safeNumber(g.dest_port) === 53 ? 1 : 0,
    smb_writes: safeNumber(g.dest_port) === 445 ? 1 : 0,

    raw_log: cleanLine,
  };
}

export async function readExistingSnortLog(filePath = config.SNORT_LOG_PATH, limit = 100) {
  if (!fs.existsSync(filePath)) {
    logger.warn(`Snort log file not found: ${filePath}`);
    return [];
  }

  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/).filter(Boolean);
  return lines.slice(-limit).map(parseSnortFastLine).filter(Boolean);
}

export function startSnortCollector(onEvent, options = {}) {
  const filePath = options.filePath || config.SNORT_LOG_PATH;
  const readExisting = options.readExisting ?? false;

  if (!config.ENABLE_SNORT) {
    logger.info("Snort collector disabled");
    return null;
  }

  if (!fs.existsSync(filePath)) {
    logger.warn(`Snort log file not found: ${filePath}`);
    return null;
  }

  logger.info(`Starting Snort collector: ${filePath}`);

  let fileSize = fs.statSync(filePath).size;

  if (readExisting) {
    readExistingSnortLog(filePath, 50).then((events) => {
      events.forEach((event) => onEvent(event));
    });
  }

  const watcher = fs.watch(filePath, async (eventType) => {
    if (eventType !== "change") return;

    try {
      const newSize = fs.statSync(filePath).size;

      if (newSize < fileSize) {
        fileSize = 0;
      }

      if (newSize === fileSize) return;

      const stream = fs.createReadStream(filePath, {
        start: fileSize,
        end: newSize,
      });

      const rl = readline.createInterface({
        input: stream,
        crlfDelay: Infinity,
      });

      for await (const line of rl) {
        const event = parseSnortFastLine(line);
        if (event) {
          onEvent(event);
        }
      }

      fileSize = newSize;
    } catch (error) {
      logger.error(`Snort collector error: ${error.message}`);
    }
  });

  return {
    stop() {
      watcher.close();
      logger.info("Snort collector stopped");
    },
  };
}