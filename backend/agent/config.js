// agent/config.js

import dotenv from "dotenv";
dotenv.config();

const config = {
  // ---------- AGENT INFO ----------
  AGENT_ID: process.env.AGENT_ID || "agent-001",
  ASSET_ID: process.env.ASSET_ID || "host-001",

  // ---------- SERVER ----------
  IDS_ENGINE_URL:
    process.env.IDS_ENGINE_URL || "http://localhost:8000/api/detect",

  IDS_BATCH_URL:
    process.env.IDS_BATCH_URL || "http://localhost:8000/api/detect/batch",

  // ---------- SECURITY ----------
  API_KEY: process.env.THREATLENS_API_KEY || "test-key",
  API_SECRET: process.env.THREATLENS_API_SECRET || "test-secret",

  // ---------- REQUEST ----------
  REQUEST_TIMEOUT: parseInt(process.env.REQUEST_TIMEOUT || "5000"),
  MAX_RETRIES: parseInt(process.env.MAX_RETRIES || "3"),

  // ---------- STREAMING ----------
  BATCH_SIZE: parseInt(process.env.BATCH_SIZE || "10"),
  FLUSH_INTERVAL: parseInt(process.env.FLUSH_INTERVAL || "5000"),

  // ---------- FEATURES ----------
  ENABLE_SNORT: process.env.ENABLE_SNORT === "true",
  ENABLE_FILE_WATCH: process.env.ENABLE_FILE_WATCH === "true",
  ENABLE_SYSTEM_MONITOR: process.env.ENABLE_SYSTEM_MONITOR !== "false",

  // ---------- PATHS ----------
  SNORT_LOG_PATH:
    process.env.SNORT_LOG_PATH || "/var/log/snort/alert_fast.txt",

  DATA_DIR: process.env.DATA_DIR || "./data",

  // ---------- LOGGING ----------
  LOG_LEVEL: process.env.LOG_LEVEL || "info",

  // ---------- MODE ----------
  MODE: process.env.AGENT_MODE || "production", // dev | production
};

export default config;