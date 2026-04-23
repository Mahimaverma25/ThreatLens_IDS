const mongoose = require("mongoose");

const config = require("./env");

let listenersAttached = false;

const attachConnectionListeners = () => {
  if (listenersAttached) {
    return;
  }

  listenersAttached = true;

  mongoose.connection.on("connected", () => {
    console.log("MongoDB connected");
  });

  mongoose.connection.on("error", (error) => {
    console.error("MongoDB error:", error.message);
  });

  mongoose.connection.on("disconnected", () => {
    console.warn("MongoDB disconnected");
  });
};

const connectDB = async () => {
  mongoose.set("strictQuery", true);
  attachConnectionListeners();

  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  await mongoose.connect(config.mongoUri, {
    serverSelectionTimeoutMS: 5000,
  });

  return mongoose.connection;
};

const disconnectDB = async () => {
  if (mongoose.connection.readyState === 0) {
    return;
  }

  await mongoose.disconnect();
  console.log("MongoDB disconnected");
};

module.exports = { connectDB, disconnectDB };
