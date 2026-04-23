#!/usr/bin/env node

/**
 * ThreatLens API key setup helper.
 *
 * Creates a local organization, asset, and API key pair for the live
 * collector flow, then syncs the generated credentials into
 * backend/collector/.env.
 */

require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const mongoose = require("mongoose");
const path = require("path");

const Asset = require("./models/Asset");
const APIKey = require("./models/APIKey");
const Organization = require("./models/Organization");
const User = require("./models/User");

async function findPrimaryOrg() {
  const adminUser = await User.findOne({ role: "admin", _org_id: { $ne: null } })
    .sort({ createdAt: 1 })
    .populate("_org_id");

  if (adminUser?._org_id) {
    return adminUser._org_id;
  }

  return Organization.findOne({ org_id: "test-org" });
}

function syncEnvFile(envPath, entries = {}) {
  let content = fs.existsSync(envPath)
    ? fs.readFileSync(envPath, "utf8")
    : "";

  const upsert = (key, value) => {
    const line = `${key}=${value}`;
    const pattern = new RegExp(`^${key}=.*$`, "m");

    if (pattern.test(content)) {
      content = content.replace(pattern, line);
    } else {
      content = `${content.trim()}\n${line}\n`.trimStart();
    }
  };

  Object.entries(entries).forEach(([key, value]) => {
    upsert(key, value);
  });

  fs.writeFileSync(
    envPath,
    content.endsWith("\n") ? content : `${content}\n`,
    "utf8"
  );
}

function syncCollectorEnv({ apiUrl, token, secret, assetId }) {
  try {
    const collectorEnvPath = path.resolve(__dirname, "..", "collector", ".env");
    syncEnvFile(collectorEnvPath, {
      THREATLENS_API_URL: apiUrl,
      THREATLENS_API_KEY: token,
      THREATLENS_API_SECRET: secret,
      ASSET_ID: assetId,
      SENSOR_TYPE: "host",
      HOST_EVENTS_PATH: path.resolve(
        __dirname,
        "..",
        "collector",
        "sample-host-events.jsonl"
      ),
      POLL_INTERVAL_SECONDS: "5",
      HEARTBEAT_INTERVAL_SECONDS: "15",
      REQUEST_TIMEOUT_SECONDS: "10",
      MAX_RETRIES: "4",
      RETRY_BACKOFF_SECONDS: "1.5",
    });

    console.log(`Synced collector credentials to ${collectorEnvPath}`);
  } catch (error) {
    console.warn("Failed to sync collector .env automatically:", error.message);
  }
}

function syncNodeAgentEnv({ apiUrl, token, secret, assetId }) {
  try {
    const agentEnvPath = path.resolve(__dirname, "..", "agent", ".env");
    syncEnvFile(agentEnvPath, {
      THREATLENS_API_URL: apiUrl.replace(/\/api\/?$/, ""),
      THREATLENS_API_KEY: token,
      THREATLENS_API_SECRET: secret,
      ASSET_ID: assetId,
      AGENT_MODE: "host",
      FILE_WATCH_ENABLED: "true",
      FILE_WATCH_PATHS: "C:\\Users\\Public,C:\\Windows\\Temp",
      SYSTEM_INTERVAL_MS: "15000",
      PROCESS_INTERVAL_MS: "12000",
      HEARTBEAT_INTERVAL_MS: "15000",
      MAX_RETRIES: "3",
    });

    console.log(`Synced Node agent credentials to ${agentEnvPath}`);
  } catch (error) {
    console.warn("Failed to sync Node agent .env automatically:", error.message);
  }
}

async function setupDevKeys() {
  try {
    const mongoUri =
      process.env.MONGO_URI || "mongodb://127.0.0.1:27017/threatlens";
    console.log(`Connecting to MongoDB: ${mongoUri}`);

    await mongoose.connect(mongoUri);
    console.log("Connected to MongoDB\n");

    console.log("Preparing project organization...");
    let org = await findPrimaryOrg();

    if (!org) {
      org = await Organization.create({
        org_id: "test-org",
        org_name: "Test Organization",
        org_plan: "starter",
        status: "active",
        ingest_quota_per_minute: 10000,
        ingest_quota_per_day: 1000000,
      });
      console.log(`Created fallback organization: ${org._id}`);
    } else {
      console.log(`Using organization: ${org.org_name} (${org._id})`);
    }

    console.log("\nCreating test asset...");
    let asset = await Asset.findOne({
      _org_id: org._id,
      asset_id: "agent-001",
    });

    if (!asset) {
      asset = await Asset.create({
        _org_id: org._id,
        asset_id: "agent-001",
        asset_name: "ThreatLens Collector",
        asset_type: "agent",
        status: "active",
        agent_status: "online",
        ip_address: "127.0.0.1",
        hostname: "test-agent",
      });
      console.log(`Created asset: ${asset._id}`);
    } else {
      console.log(`Asset already exists: ${asset._id}`);
    }

    console.log("\nCreating API key...");

    const existingKey = await APIKey.findOne({
      _org_id: org._id,
      _asset_id: asset._id,
      is_active: true,
    });

    if (existingKey) {
      console.log("Active API key already exists for this asset");
      console.log(`Deactivating old key: ${existingKey.token}`);
      existingKey.is_active = false;
      await existingKey.save();
    }

    const token = `tlk_${org._id.toString().slice(-8)}_${crypto
      .randomBytes(16)
      .toString("hex")}`;
    const secret = crypto.randomBytes(32).toString("hex");
    const secretHash = crypto.createHash("sha256").update(secret).digest("hex");

    const apiKey = await APIKey.create({
      token,
      secret_key_hash: secretHash,
      _org_id: org._id,
      _asset_id: asset._id,
      key_name: "Collector Test Key",
      is_active: true,
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    });

    console.log(`Created API key: ${apiKey._id}`);
    console.log("\nAPI KEY CREDENTIALS (save these):\n");
    console.log(`Token:  ${token}`);
    console.log(`Secret: ${secret}`);
    console.log(`Asset:  ${asset.asset_id}`);

    const apiPort = process.env.PORT || "5000";
    const apiUrl = `http://localhost:${apiPort}/api`;

    console.log(`\n${"=".repeat(60)}`);
    console.log("SETUP COMPLETE - use these values in your collector .env:");
    console.log(`${"=".repeat(60)}\n`);
    console.log(`THREATLENS_API_URL=${apiUrl}`);
    console.log(`THREATLENS_API_KEY=${apiKey.token}`);
    console.log(`THREATLENS_API_SECRET=${secret}`);
    console.log(`ASSET_ID=${asset.asset_id}`);
    console.log(`\n${"=".repeat(60)}\n`);

    syncCollectorEnv({
      apiUrl,
      token: apiKey.token,
      secret,
      assetId: asset.asset_id,
    });
    syncNodeAgentEnv({
      apiUrl,
      token: apiKey.token,
      secret,
      assetId: asset.asset_id,
    });

    console.log("Verifying API key setup...");
    const verifyKey = await APIKey.findOne({
      token: apiKey.token,
      is_active: true,
    })
      .populate("_org_id")
      .populate("_asset_id");

    if (verifyKey && verifyKey._org_id && verifyKey._asset_id) {
      console.log("API key verified successfully!");
      console.log(`Organization: ${verifyKey._org_id.org_name}`);
      console.log(`Asset: ${verifyKey._asset_id.asset_name}`);
      console.log(`Status: ${verifyKey.is_active ? "ACTIVE" : "INACTIVE"}`);
      console.log(`Expires: ${verifyKey.expires_at}`);
    } else {
      console.log("Verification failed!");
    }

    console.log(
      "\nSetup complete! You can now start the collector with the credentials above.\n"
    );
    process.exit(0);
  } catch (error) {
    console.error("Setup failed:", error);
    process.exit(1);
  }
}

setupDevKeys();
