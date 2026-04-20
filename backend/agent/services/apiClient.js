const axios = require("axios");
require("dotenv").config();

const { SIGNATURE_VERSION, buildSignature } = require("../ingest-signature");

const apiClient = axios.create({
  baseURL: process.env.THREATLENS_API_URL,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
    "x-api-key": process.env.THREATLENS_API_KEY,
  },
});

async function sendEvent(payload) {
  try {
    const timestamp = Date.now().toString();
    const signature = buildSignature({
      apiSecret: process.env.THREATLENS_API_SECRET || "",
      timestamp,
      assetId: process.env.ASSET_ID || "",
      body: payload,
    });

    const response = await apiClient.post("/api/logs/ingest", payload, {
      headers: {
        "x-timestamp": timestamp,
        "x-signature": signature,
        "x-signature-version": SIGNATURE_VERSION,
        "x-asset-id": process.env.ASSET_ID,
      },
    });

    console.log("Event sent:", response.data);
  } catch (error) {
    if (error.response) {
      console.error("Backend response:", error.response.data);
    } else {
      console.error("Network error:", error.message);
    }
  }
}

module.exports = {
  sendEvent,
};
