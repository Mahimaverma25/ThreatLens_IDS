/**
 * Setup script to create initial API key for agent
 * Run once before starting agent: node setup-api-key.js
 */

require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const config = require("./config/env");
const Organization = require("./models/Organization");
const Asset = require("./models/Asset");
const APIKey = require("./models/APIKey");

async function setup() {
  try {
    console.log("🔧 Connecting to MongoDB...");
    await mongoose.connect(config.dbUrl);
    console.log("✓ Connected");

    // 1. Create organization if it doesn't exist
    console.log("\n📦 Setting up Organization...");
    let org = await Organization.findOne({ org_id: "dev-org" });
    if (!org) {
      org = await Organization.create({
        org_id: "dev-org",
        org_name: "Development Organization",
        org_plan: "enterprise",
        org_status: "active",
        ingest_quota_per_minute: 10000,
        ingest_quota_per_day: 1000000,
        feature_flags: {
          real_time_alerts: true,
          correlation_engine: true,
          anomaly_detection: true,
          threat_intel: true
        },
        data_retention_days: 30
      });
      console.log(`✓ Organization created: ${org._id}`);
    } else {
      console.log(`✓ Organization exists: ${org._id}`);
    }

    // 2. Create asset if it doesn't exist
    console.log("\n🖥️  Setting up Asset...");
    let asset = await Asset.findOne({
      _org_id: org._id,
      asset_id: "asset-dev-laptop"
    });
    if (!asset) {
      asset = await Asset.create({
        asset_id: "asset-dev-laptop",
        asset_name: "Development Laptop",
        asset_type: "web_server",
        asset_criticality: "high",
        hostname: "localhost",
        ip_address: "127.0.0.1",
        _org_id: org._id,
        asset_status: "active",
        agent_status: "pending",
        baseline: {
          avg_requests_per_minute: 100,
          typical_users: ["dev", "admin"],
          typical_geographies: ["local"]
        },
        suppression_rules: []
      });
      console.log(`✓ Asset created: ${asset._id}`);
    } else {
      console.log(`✓ Asset exists: ${asset._id}`);
    }

    // 3. Create API key if it doesn't exist
    console.log("\n🔑 Setting up API Key...");
    let apiKey = await APIKey.findOne({ token: "key_test_agent_001" });
    if (!apiKey) {
      const token = "key_test_agent_001";
      const secret = "secret_very_secure_test_key";
      
      apiKey = await APIKey.create({
        token,
        secret_key_hash: bcrypt.hashSync(secret, 12),
        _org_id: org._id,
        _asset_id: asset._id,
        key_name: "Development Agent Key",
        created_by: "setup-script",
        expiration_days: null,
        is_active: true
      });
      console.log(`✓ API Key created: ${apiKey._id}`);
      console.log(`\n📋 Save these credentials (secret shown only once):`);
      console.log(`   API Key Token: ${token}`);
      console.log(`   API Secret:    ${secret}`);
    } else {
      console.log(`✓ API Key exists: ${apiKey._id}`);
    }

    console.log("\n✅ Setup complete!");
    console.log("\n📝 Agent .env file should contain:");
    console.log(`   THREATLENS_API_URL=http://localhost:3000`);
    console.log(`   THREATLENS_API_KEY=key_test_agent_001`);
    console.log(`   THREATLENS_API_SECRET=secret_very_secure_test_key`);
    console.log(`   ASSET_ID=asset-dev-laptop`);
    console.log("\n🚀 Run agent with: npm start");

    await mongoose.connection.close();
    process.exit(0);
  } catch (error) {
    console.error("❌ Setup failed:", error.message);
    process.exit(1);
  }
}

setup();
