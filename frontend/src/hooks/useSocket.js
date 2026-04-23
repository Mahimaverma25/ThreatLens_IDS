import { useEffect, useRef, useState } from "react";
import createSocketClient from "../services/socket";

const useSocket = (token, handlers = {}) => {
  const socketRef = useRef(null);
  const handlersRef = useRef(handlers);
  const [connectionStatus, setConnectionStatus] = useState(token ? "connecting" : "idle");
  const [lastConnectedAt, setLastConnectedAt] = useState(null);
  const [lastDisconnectedAt, setLastDisconnectedAt] = useState(null);
  const [lastError, setLastError] = useState("");

  useEffect(() => {
    handlersRef.current = handlers;
  }, [handlers]);

  useEffect(() => {
    if (!token) {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      setConnectionStatus("idle");
      return undefined;
    }

    const socket = createSocketClient(token);
    socketRef.current = socket;
    setConnectionStatus("connecting");

    const attachHandlers = () => {
      Object.entries(handlersRef.current || {}).forEach(([event, handler]) => {
        socket.off(event);
        socket.on(event, handler);
      });
    };

    const handleConnect = () => {
      setConnectionStatus("connected");
      setLastConnectedAt(new Date().toISOString());
      setLastError("");
      attachHandlers();
    };

    const handleDisconnect = () => {
      setConnectionStatus("disconnected");
      setLastDisconnectedAt(new Date().toISOString());
    };

    const handleError = (error) => {
      setConnectionStatus("error");
      setLastError(error?.message || "Socket connection error");
    };

    socket.on("connect", handleConnect);
    socket.on("disconnect", handleDisconnect);
    socket.on("connect_error", handleError);
    attachHandlers();

    return () => {
      socket.off("connect", handleConnect);
      socket.off("disconnect", handleDisconnect);
      socket.off("connect_error", handleError);
      Object.entries(handlersRef.current || {}).forEach(([event, handler]) => {
        socket.off(event, handler);
      });
      socket.disconnect();
      socketRef.current = null;
    };
  }, [token]);

  useEffect(() => {
    const socket = socketRef.current;
    if (!socket) {
      return undefined;
    }

    Object.entries(handlersRef.current || {}).forEach(([event, handler]) => {
      socket.off(event);
      socket.on(event, handler);
    });

    return () => {
      Object.entries(handlersRef.current || {}).forEach(([event, handler]) => {
        socket.off(event, handler);
      });
    };
  }, [handlers]);

  return {
    socket: socketRef.current,
    isConnected: connectionStatus === "connected",
    connectionStatus,
    lastConnectedAt,
    lastDisconnectedAt,
    lastError,
  };
};

export default useSocket;
