let ioInstance;

const orgRoom = (orgId) => `org:${orgId}`;
const roleRoom = (role) => `role:${role}`;

const initSocket = (httpServer) => {
  const { Server } = require("socket.io");
  const jwt = require("jsonwebtoken");

  const config = require("./config/env");
  const { normalizeRole } = require("./utils/roles");

  ioInstance = new Server(httpServer, {
    cors: {
      origin: config.corsOrigins,
      credentials: true,
    },
  });

  ioInstance.use((socket, next) => {
    const token =
      socket.handshake.auth?.token ||
      socket.handshake.headers?.authorization?.replace(/^Bearer\s+/i, "");

    if (!token) {
      console.log("❌ Socket auth failed: missing token");
      return next(new Error("Unauthorized"));
    }

    try {
      const payload = jwt.verify(token, config.jwtSecret);

      socket.user = {
        ...payload,
        role: normalizeRole(payload.role),
        orgId: payload.orgId || payload._org_id || null,
      };

      console.log(
        `✅ Socket authenticated | role=${socket.user.role} | org=${socket.user.orgId || "none"}`
      );

      return next();
    } catch (error) {
      console.log("❌ Socket auth failed: invalid token");
      return next(new Error("Unauthorized"));
    }
  });

  ioInstance.on("connection", (socket) => {
    console.log(
      `🔌 Socket connected | id=${socket.id} | role=${socket.user.role} | org=${socket.user.orgId || "none"}`
    );

    socket.join(roleRoom(socket.user.role));

    if (socket.user.orgId) {
      socket.join(orgRoom(socket.user.orgId.toString()));
    }

    socket.emit("socket:ready", {
      organizationId: socket.user.orgId || null,
      role: socket.user.role,
      message: "Socket connection established",
    });

    socket.on("disconnect", (reason) => {
      console.log(`⚠️ Socket disconnected | id=${socket.id} | reason=${reason}`);
    });
  });

  return ioInstance;
};

const getIo = () => {
  if (!ioInstance) {
    throw new Error("Socket.io not initialized");
  }
  return ioInstance;
};

const emitToOrganization = (orgId, eventName, payload = {}) => {
  if (!orgId) {
    console.log(`⚠️ Skipped emit: missing orgId for event "${eventName}"`);
    return;
  }

  try {
    const room = orgRoom(orgId.toString());
    getIo().to(room).emit(eventName, payload);
    console.log(`📡 Emitted "${eventName}" to ${room}`);
  } catch (error) {
    console.log(`❌ Failed to emit "${eventName}" to org ${orgId}: ${error.message}`);
  }
};

const emitToRole = (role, eventName, payload = {}) => {
  if (!role) {
    console.log(`⚠️ Skipped emit: missing role for event "${eventName}"`);
    return;
  }

  try {
    const room = roleRoom(role);
    getIo().to(room).emit(eventName, payload);
    console.log(`📡 Emitted "${eventName}" to ${room}`);
  } catch (error) {
    console.log(`❌ Failed to emit "${eventName}" to role ${role}: ${error.message}`);
  }
};

const emitGlobal = (eventName, payload = {}) => {
  try {
    getIo().emit(eventName, payload);
    console.log(`📡 Emitted global event "${eventName}"`);
  } catch (error) {
    console.log(`❌ Failed to emit global event "${eventName}": ${error.message}`);
  }
};

module.exports = {
  initSocket,
  getIo,
  emitToOrganization,
  emitToRole,
  emitGlobal,
  orgRoom,
  roleRoom,
};