#!/usr/bin/env node

/**
 * ThreatLens API Key Setup Helper
 * 
 * This script creates a test organization, asset, and API key
 * for local development and agent testing.
 * 
 * Usage: node setup-dev-keys.js
 */

require("dotenv").config();
const mongoose = require("mongoose");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Models
const Organization = require("./models/Organization");
const Asset = require("./models/Asset");
const APIKey = require("./models/APIKey");
const User = require("./models/User");

function syncAgentEnv({ apiUrl, token, secret, assetId }) {
  try {
    const agentEnvPath = path.resolve(__dirname, "..", "agent", ".env");
    let content = "";

    if (fs.existsSync(agentEnvPath)) {
      content = fs.readFileSync(agentEnvPath, "utf8");
    }

    const upsert = (key, value) => {
      const line = `${key}=${value}`;
      const pattern = new RegExp(`^${key}=.*$`, "m");
      if (pattern.test(content)) {
        content = content.replace(pattern, line);
      } else {
        content = `${content.trim()}\n${line}\n`.trimStart();
      }
    };

    upsert("THREATLENS_API_URL", apiUrl);
    upsert("THREATLENS_API_KEY", token);
    upsert("THREATLENS_API_SECRET", secret);
    upsert("ASSET_ID", assetId);

    if (!/LOG_LEVEL=/m.test(content)) {
      content += `${content.endsWith("\n") ? "" : "\n"}LOG_LEVEL=info\n`;
    }
    if (!/BATCH_SIZE=/m.test(content)) {
      content += "BATCH_SIZE=20\n";
    }
    if (!/BATCH_TIMEOUT_MS=/m.test(content)) {
      content += "BATCH_TIMEOUT_MS=10000\n";
    }
    if (!/HEALTH_CHECK_INTERVAL_MS=/m.test(content)) {
      content += "HEALTH_CHECK_INTERVAL_MS=60000\n";
    }

    fs.writeFileSync(agentEnvPath, content.endsWith("\n") ? content : `${content}\n`, "utf8");
    console.log(`✅ Synced agent credentials to ${agentEnvPath}`);
  } catch (error) {
    console.warn("⚠ Failed to sync agent .env automatically:", error.message);
  }
}

async function setupDevKeys() {
  try {
    // Connect to MongoDB
    const mongoUri = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/threatlens";
    console.log(`📡 Connecting to MongoDB: ${mongoUri}`);
    
    await mongoose.connect(mongoUri);
    console.log("✅ Connected to MongoDB\n");

    // Create test organization
    console.log("🏢 Creating test organization...");
    let org = await Organization.findOne({ org_id: "test-org" });
    
    if (!org) {
      org = await Organization.create({
        org_id: "test-org",
        org_name: "Test Organization",
        org_plan: "starter",
        status: "active",
        ingest_quota_per_minute: 10000,
        ingest_quota_per_day: 1000000
      });
      console.log(`✅ Created organization: ${org._id}`);
    } else {
      console.log(`✅ Organization already exists: ${org._id}`);
    }

    // Create test asset
    console.log("\n🖥️  Creating test asset...");
    let asset = await Asset.findOne({
      _org_id: org._id,
      asset_id: "agent-001"
    });

    if (!asset) {
      asset = await Asset.create({
        _org_id: org._id,
        asset_id: "agent-001",
        asset_name: "Test Agent",
        asset_type: "agent",
        status: "active",
        agent_status: "online",
        ip_address: "127.0.0.1",
        hostname: "test-agent"
      });
      console.log(`✅ Created asset: ${asset._id}`);
    } else {
      console.log(`✅ Asset already exists: ${asset._id}`);
    }

    // Create API key
    console.log("\n🔑 Creating API key...");
    
    // Check if key already exists
    let existingKey = await APIKey.findOne({
      _org_id: org._id,
      _asset_id: asset._id,
      is_active: true
    });

    let apiKey;
    let generatedSecret = null;
    if (existingKey) {
      console.log(`⚠️  Active API key already exists for this asset`);
      console.log(`   Deactivating old key: ${existingKey.token}`);
      existingKey.is_active = false;
      await existingKey.save();
    }

    // Generate token and secret
    const token = `tlk_${org._id.toString().slice(-8)}_${crypto.randomBytes(16).toString("hex")}`;
    const secret = crypto.randomBytes(32).toString("hex");
    const secretHash = crypto.createHash("sha256").update(secret).digest("hex");
    generatedSecret = secret;

    apiKey = await APIKey.create({
      token,
      secret_key_hash: secretHash,
      _org_id: org._id,
      _asset_id: asset._id,
      key_name: "Agent Test Key",
      is_active: true,
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
    });

    console.log(`✅ Created API key: ${apiKey._id}`);
    console.log(`\n📋 API KEY CREDENTIALS (Save these!):\n`);
    console.log(`   Token:  ${token}`);
    console.log(`   Secret: ${secret}`);
    console.log(`   Asset:  ${asset.asset_id}`);

    // Display summary
    const apiPort = process.env.PORT || "5000";
    const apiUrl = `http://localhost:${apiPort}`;

    console.log(`\n${'='.repeat(60)}`);
    console.log("📊 SETUP COMPLETE - Use these values in your agent .env:");
    console.log(`${'='.repeat(60)}\n`);
    console.log(`THREATLENS_API_URL=${apiUrl}`);
    console.log(`THREATLENS_API_KEY=${apiKey.token}`);
    console.log(`THREATLENS_API_SECRET=${generatedSecret}`);
    console.log(`ASSET_ID=${asset.asset_id}`);
    console.log(`\n${'='.repeat(60)}\n`);

    syncAgentEnv({
      apiUrl,
      token: apiKey.token,
      secret: generatedSecret,
      assetId: asset.asset_id
    });

    // Verify the API key works
    console.log("🔍 Verifying API key setup...");
    const verifyKey = await APIKey.findOne({
      token: apiKey.token,
      is_active: true
    }).populate("_org_id").populate("_asset_id");

    if (verifyKey && verifyKey._org_id && verifyKey._asset_id) {
      console.log("✅ API key verified successfully!");
      console.log(`   - Organization: ${verifyKey._org_id.org_name}`);
      console.log(`   - Asset: ${verifyKey._asset_id.asset_name}`);
      console.log(`   - Status: ${verifyKey.is_active ? 'ACTIVE' : 'INACTIVE'}`);
      console.log(`   - Expires: ${verifyKey.expires_at}`);
    } else {
      console.log("❌ Verification failed!");
    }

    console.log("\n✅ Setup complete! You can now start the agent with the credentials above.\n");
    process.exit(0);

  } catch (error) {
    console.error("❌ Setup failed:", error);
    process.exit(1);
  }
}

// Run setup
setupDevKeys();
