const axios = require("axios");
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
    const response = await apiClient.post(
      "/api/ingest/v1/ingest",
      payload
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