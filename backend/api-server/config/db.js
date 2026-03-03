const mongoose = require("mongoose");
const config = require("./env");

const connectDB = async () => {
  try {
    await mongoose.connect(config.mongoUri, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log("✓ MongoDB connected successfully");
    return mongoose.connection;
  } catch (error) {
    console.error("✗ MongoDB connection error:", error.message);
    process.exit(1);
  }
};

const disconnectDB = async () => {
  try {
    await mongoose.disconnect();
    console.log("✓ MongoDB disconnected");
  } catch (error) {
    console.error("✗ MongoDB disconnection error:", error.message);
    process.exit(1);
  }
};

module.exports = { connectDB, disconnectDB };
