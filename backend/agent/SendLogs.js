const axios = require("axios");

const API_URL = "http://localhost:5000/api/logs/ingest";

// ⚠️ Replace with your actual key from .env
const API_KEY = "880a3e3ac6c61144ef6ba20123d10e4272b45642dfe070c6427c6fac7f253e61";
const ORG_ID = "69c69322158c10ad1914c0b3";

const sendLog = async () => {
  try {
    const response = await axios.post(
      API_URL,
      {
        logs: [
           {
            message: "Test log from agent",
            level: "info",
            source: "agent",
            eventType: "test_event",
            metadata: { status: "ok" },
            asset_id: "agent-001",
            timestamp: new Date().toISOString()
          }
        ]
      },
      {
        headers: {
          "Content-Type": "application/json",
          "X-api-Key": API_KEY,
          "x-org-id": ORG_ID
        }
      }
    );

    console.log("✅ Log sent:", response.data);
  } catch (error) {
    console.error("❌ Error:", error.response?.data || error.message);
  }
};

// send every 10 seconds
setInterval(sendLog, 10000);