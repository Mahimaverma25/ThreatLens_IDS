/**
 * ThreatLens Agent Entry Point
 * Supports:
 * - Snort real-time mode
 * - Simulated/demo mode
 * - Future extensibility
 */

require("dotenv").config();

console.log("🚀 Starting ThreatLens Agent...");

// ================= CONFIG =================
const MODE = String(process.env.AGENT_MODE || "snort").trim().toLowerCase();
const API_URL = String(process.env.THREATLENS_API_URL || "").trim();
const API_KEY = String(process.env.THREATLENS_API_KEY || "").trim();
const SNORT_FAST_LOG_PATH = String(process.env.SNORT_FAST_LOG_PATH || "").trim();
const SNORT_EVE_JSON_PATH = String(process.env.SNORT_EVE_JSON_PATH || "").trim();

console.log(`📌 Agent Mode: ${MODE.toUpperCase()}`);
console.log(`🌐 Backend URL: ${API_URL || "(missing)"}`);

if (SNORT_FAST_LOG_PATH) {
  console.log(`📂 Snort Fast Log: ${SNORT_FAST_LOG_PATH}`);
}
if (SNORT_EVE_JSON_PATH) {
  console.log(`📂 Snort EVE JSON: ${SNORT_EVE_JSON_PATH}`);
}

// ================= VALIDATION =================
if (!API_URL) {
  console.error("❌ Missing THREATLENS_API_URL in .env");
  process.exit(1);
}

if (!API_KEY) {
  console.warn("⚠️ Missing THREATLENS_API_KEY (ingestion may fail)");
}

if (MODE === "snort" && !SNORT_FAST_LOG_PATH && !SNORT_EVE_JSON_PATH) {
  console.warn(
    "⚠️ No Snort log path configured. Set SNORT_FAST_LOG_PATH or SNORT_EVE_JSON_PATH in .env"
  );
}

// ================= MODE HANDLER =================
try {
  if (MODE === "snort") {
    console.log("🛡️ Running in REAL-TIME SNORT mode...");
    require("./realtime-agent");
  } else if (MODE === "demo") {
    console.log("🎯 Running in DEMO mode...");
    require("./demo-agent");
  } else {
    console.error(`❌ Invalid AGENT_MODE "${MODE}". Use "snort" or "demo"`);
    process.exit(1);
  }
} catch (err) {
  console.error("🔥 Agent failed to start:");
  console.error(err && err.stack ? err.stack : err.message || err);
  process.exit(1);
}

// ================= HEARTBEAT LOG =================
setInterval(() => {
  console.log("💓 Agent is alive...");
}, 60000);