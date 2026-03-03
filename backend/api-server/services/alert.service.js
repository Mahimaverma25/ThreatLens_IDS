const { v4: uuidv4 } = require("uuid");
const Alert = require("../models/Alerts");
const { getIo } = require("../socket");

const createAlert = async (payload) => {
  const alert = await Alert.create({
    alertId: uuidv4(),
    ...payload
  });

  try {
    const io = getIo();
    io.emit("alerts:new", alert);
  } catch (error) {
    // Socket not initialized in tests or early startup.
  }

  return alert;
};

const updateAlert = async (alert) => {
  try {
    const io = getIo();
    io.emit("alerts:update", alert);
  } catch (error) {
    // noop
  }
};

module.exports = { createAlert, updateAlert };
