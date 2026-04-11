let ioInstance;

const initSocket = (httpServer) => {
  const { Server } = require("socket.io");
  const config = require("./config/env");
  const jwt = require("jsonwebtoken");

  ioInstance = new Server(httpServer, {
    cors: {
      origin: config.corsOrigins,
      credentials: true
    }
  });

  ioInstance.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) {
      return next(new Error("Unauthorized"));
    }

    try {
      const payload = jwt.verify(token, config.jwtSecret);
      socket.user = payload;
      return next();
    } catch (error) {
      return next(new Error("Unauthorized"));
    }
  });

  ioInstance.on("connection", (socket) => {
    socket.join(`role:${socket.user.role}`);
  });

  return ioInstance;
};

const getIo = () => {
  if (!ioInstance) {
    throw new Error("Socket.io not initialized");
  }
  return ioInstance;
};

module.exports = { initSocket, getIo };
