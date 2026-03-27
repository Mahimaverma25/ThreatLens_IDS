/**
 * Setup script to create org + API key for agent (UPDATED)
 * Run: node setup-api-key.js
 */

require("dotenv").config();
const mongoose = require("mongoose");
const crypto = require("crypto");

const config = require("./config/env");
const Organization = require("./models/Organization");
const Asset = require("./models/Asset");

function generateApiKey() {
  return crypto.randomBytes(32).toString("hex");
}

async function setup() {
  try {
    console.log("🔧 Connecting to MongoDB...");
    await mongoose.connect(config.dbUrl);
    console.log("✓ Connected");

    // =========================
    // 🏢 1. CREATE ORGANIZATION
    // =========================
    console.log("\n📦 Setting up Organization...");

    let org = await Organization.findOne({ name: "Mahima Org" });

    if (!org) {
      const apiKey = generateApiKey();

      org = await Organization.create({
        name: "Mahima Org",
        agent_api_key: apiKey,
        status: "active",
        createdAt: new Date()
      });

      console.log(`✓ Organization created: ${org._id}`);
      console.log(`🔑 API KEY: ${apiKey}`);
    } else {
      console.log(`✓ Organization exists: ${org._id}`);
      console.log(`🔑 API KEY: ${org.agent_api_key}`);
    }

    // =========================
    // 🖥️ 2. CREATE ASSET
    // =========================
    console.log("\n🖥️ Setting up Asset...");

    let asset = await Asset.findOne({
      asset_id: "agent-001",
      _org_id: org._id
    });

    if (!asset) {
      asset = await Asset.create({
        asset_id: "agent-001",
        asset_name: "Local Agent",
        asset_type: "server",
        ip_address: "127.0.0.1",
        _org_id: org._id,
        asset_status: "active"
      });

      console.log(`✓ Asset created: ${asset._id}`);
    } else {
      console.log(`✓ Asset exists: ${asset._id}`);
    }

    // =========================
    // 📋 FINAL OUTPUT
    // =========================
    console.log("\n✅ Setup complete!");

    console.log("\n📋 Use these in your AGENT .env:\n");

    console.log(`THREATLENS_API_URL=http://localhost:5000`);
    console.log(`THREATLENS_API_KEY=${org.agent_api_key}`);
    console.log(`ORG_ID=${org._id}`);
    console.log(`ASSET_ID=agent-001`);

    console.log("\n🚀 Now start your agent!");

    await mongoose.connection.close();
    process.exit(0);

  } catch (error) {
    console.error("❌ Setup failed:", error.message);
    process.exit(1);
  }
}

setup();