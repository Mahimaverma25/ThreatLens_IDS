let ioInstance = null;

const orgRoom = (orgId) => `org:${orgId}`;
const roleRoom = (role) => `role:${role}`;
const shouldLogSocketEvents = process.env.LOG_SOCKET_EVENTS === "true";

const logSocketEvent = (message) => {
  if (shouldLogSocketEvents) {
    console.log(message);
  }
};

const normalizeOrigins = (origins) => {
  if (!origins) return [];

  if (Array.isArray(origins)) {
    return origins.map((origin) => String(origin).trim()).filter(Boolean);
  }

  return String(origins)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
};

const initSocket = (httpServer) => {
  const { Server } = require("socket.io");
  const jwt = require("jsonwebtoken");

  const config = require("./config/env");
  const { normalizeRole } = require("./utils/roles");

  if (ioInstance) {
    return ioInstance;
  }

  const allowedOrigins = normalizeOrigins(
    config.corsOrigins || config.corsOrigin || process.env.CORS_ORIGIN
  );

  ioInstance = new Server(httpServer, {
    cors: {
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);

        if (allowedOrigins.length === 0 && config.nodeEnv !== "production") {
          return callback(null, true);
        }

        if (config.nodeEnv !== "production") {
          try {
            const parsed = new URL(origin);
            if (
              parsed.hostname === "localhost" ||
              parsed.hostname === "127.0.0.1"
            ) {
              return callback(null, true);
            }
          } catch {
            return callback(new Error("Socket CORS origin not allowed"));
          }
        }

        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        }

        return callback(new Error("Socket CORS origin not allowed"));
      },
      credentials: true,
      methods: ["GET", "POST"],
    },
    transports: ["websocket", "polling"],
    pingTimeout: 30000,
    pingInterval: 25000,
  });

  ioInstance.use((socket, next) => {
    const authToken = socket.handshake.auth?.token;
    const headerToken = socket.handshake.headers?.authorization?.replace(
      /^Bearer\s+/i,
      ""
    );

    const queryToken = socket.handshake.query?.token;

    const token = authToken || headerToken || queryToken;

    if (!token) {
      logSocketEvent("Socket auth failed: missing token");
      return next(new Error("Unauthorized"));
    }

    try {
      const payload = jwt.verify(String(token), config.jwtSecret);

      const orgId =
        payload.orgId ||
        payload._org_id ||
        payload.organizationId ||
        payload.organization_id ||
        null;

      socket.user = {
        ...payload,
        id: payload.sub || payload.id || payload._id || null,
        role: normalizeRole(payload.role || "viewer"),
        orgId: orgId ? orgId.toString() : null,
      };

      logSocketEvent(
        `Socket authenticated | id=${socket.user.id || "unknown"} | role=${
          socket.user.role
        } | org=${socket.user.orgId || "none"}`
      );

      return next();
    } catch (error) {
      logSocketEvent(`Socket auth failed: ${error.message}`);
      return next(new Error("Unauthorized"));
    }
  });

  ioInstance.on("connection", (socket) => {
    const role = socket.user?.role || "viewer";
    const orgId = socket.user?.orgId || null;

    logSocketEvent(
      `Socket connected | id=${socket.id} | role=${role} | org=${
        orgId || "none"
      }`
    );

    socket.join(roleRoom(role));

    if (orgId) {
      socket.join(orgRoom(orgId));
    }

    socket.emit("socket:ready", {
      success: true,
      socketId: socket.id,
      organizationId: orgId,
      role,
      rooms: {
        organization: orgId ? orgRoom(orgId) : null,
        role: roleRoom(role),
      },
      message: "ThreatLens realtime connection established",
      timestamp: new Date().toISOString(),
    });

    socket.on("dashboard:subscribe", () => {
      if (orgId) {
        socket.join(orgRoom(orgId));
      }

      socket.emit("dashboard:subscribed", {
        success: true,
        organizationId: orgId,
        timestamp: new Date().toISOString(),
      });
    });

    socket.on("live:subscribe", () => {
      if (orgId) {
        socket.join(orgRoom(orgId));
      }

      socket.emit("live:subscribed", {
        success: true,
        organizationId: orgId,
        timestamp: new Date().toISOString(),
      });
    });

    socket.on("alerts:subscribe", () => {
      if (orgId) {
        socket.join(orgRoom(orgId));
      }

      socket.emit("alerts:subscribed", {
        success: true,
        organizationId: orgId,
        timestamp: new Date().toISOString(),
      });
    });

    socket.on("ping:client", () => {
      socket.emit("pong:server", {
        success: true,
        timestamp: new Date().toISOString(),
      });
    });

    socket.on("disconnect", (reason) => {
      logSocketEvent(
        `Socket disconnected | id=${socket.id} | reason=${reason}`
      );
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
    logSocketEvent(`Skipped emit: missing orgId for event "${eventName}"`);
    return false;
  }

  try {
    const room = orgRoom(orgId.toString());

    getIo().to(room).emit(eventName, {
      ...payload,
      organizationId: orgId.toString(),
      emittedAt: new Date().toISOString(),
    });

    logSocketEvent(`Emitted "${eventName}" to ${room}`);
    return true;
  } catch (error) {
    logSocketEvent(
      `Failed to emit "${eventName}" to org ${orgId}: ${error.message}`
    );
    return false;
  }
};

const emitToRole = (role, eventName, payload = {}) => {
  if (!role) {
    logSocketEvent(`Skipped emit: missing role for event "${eventName}"`);
    return false;
  }

  try {
    const room = roleRoom(role);

    getIo().to(room).emit(eventName, {
      ...payload,
      role,
      emittedAt: new Date().toISOString(),
    });

    logSocketEvent(`Emitted "${eventName}" to ${room}`);
    return true;
  } catch (error) {
    logSocketEvent(
      `Failed to emit "${eventName}" to role ${role}: ${error.message}`
    );
    return false;
  }
};

const emitGlobal = (eventName, payload = {}) => {
  try {
    getIo().emit(eventName, {
      ...payload,
      emittedAt: new Date().toISOString(),
    });

    logSocketEvent(`Emitted global event "${eventName}"`);
    return true;
  } catch (error) {
    logSocketEvent(`Failed to emit global event "${eventName}": ${error.message}`);
    return false;
  }
};

const isSocketReady = () => Boolean(ioInstance);

module.exports = {
  initSocket,
  getIo,
  emitToOrganization,
  emitToRole,
  emitGlobal,
  isSocketReady,
  orgRoom,
  roleRoom,
};