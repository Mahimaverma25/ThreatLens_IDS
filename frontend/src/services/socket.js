import { io } from "socket.io-client";
import { getActiveSocketUrl } from "./connection";

export const LIVE_SOCKET_EVENTS = {
  SOCKET_READY: "socket:ready",
  LOG_NEW: "logs:new",
  ALERT_NEW: "alerts:new",
  ALERT_UPDATE: "alerts:update",
  DASHBOARD_UPDATE: "dashboard:update",
  COLLECTOR_HEARTBEAT: "collector:heartbeat",
  STREAM_EVENT: "stream:event",
};

export const SOCKET_URL = getActiveSocketUrl();

export const createSocketClient = (token) =>
  io(getActiveSocketUrl(), {
    auth: token ? { token } : {},
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 10000,
  });

export default createSocketClient;
