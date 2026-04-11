const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const apiClient = axios.create({
  baseURL: process.env.THREATLENS_API_URL,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
    "x-api-key": process.env.THREATLENS_API_KEY
  }
});

async function sendEvent(payload) {
  try {
    const timestamp = Date.now().toString();
    const body = JSON.stringify(payload);
    const signature = crypto
      .createHmac("sha256", process.env.THREATLENS_API_SECRET || "")
      .update(`${timestamp}.${body}`)
      .digest("hex");

    const response = await apiClient.post(
      "/api/logs/ingest",
      payload,
      {
        headers: {
          "x-api-secret": process.env.THREATLENS_API_SECRET,
          "x-timestamp": timestamp,
          "x-signature": signature,
          "x-asset-id": process.env.ASSET_ID
        }
      }
    );

    console.log("✅ Event sent:", response.data);
  } catch (error) {
    if (error.response) {
      console.error("❌ Backend response:", error.response.data);
    } else {
      console.error("❌ Network error:", error.message);
    }
  }
}

module.exports = {
  sendEvent
};