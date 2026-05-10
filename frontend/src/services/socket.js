import { io } from "socket.io-client";
import { getActiveSocketUrl } from "./connection";

export const LIVE_SOCKET_EVENTS = {
  SOCKET_READY: "socket:ready",
  LOG_NEW: "logs:new",
  LOG_NEW_ALT: "log:new",
  ALERT_NEW: "alerts:new",
  ALERT_NEW_ALT: "alert:new",
  ALERT_UPDATE: "alerts:update",
  DASHBOARD_UPDATE: "dashboard:update",
  HEALTH_UPDATE: "health:update",
  COLLECTOR_HEARTBEAT: "collector:heartbeat",
  STREAM_EVENT: "stream:event",
};

const normalizeSocketUrl = (url = "") => {
  const clean = String(url || "http://localhost:5001").replace(/\/+$/, "");
  return clean.endsWith("/api") ? clean.replace(/\/api$/, "") : clean;
};

export const SOCKET_URL = normalizeSocketUrl(getActiveSocketUrl());

export const createSocketClient = (token) => {
  const socketUrl = normalizeSocketUrl(getActiveSocketUrl());

  return io(socketUrl, {
    auth: token ? { token } : {},
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 10000,
    autoConnect: false,
    forceNew: true,
  });
};

export default createSocketClient;