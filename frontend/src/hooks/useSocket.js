import { useEffect, useMemo, useRef, useState } from "react";
import createSocketClient from "../services/socket";

const useSocket = (token, handlers = {}) => {
  const socketRef = useRef(null);
  const handlersRef = useRef(handlers);

  const [connectionStatus, setConnectionStatus] = useState(
    token ? "connecting" : "idle"
  );
  const [lastConnectedAt, setLastConnectedAt] = useState(null);
  const [lastDisconnectedAt, setLastDisconnectedAt] = useState(null);
  const [lastError, setLastError] = useState("");

  const handlerKeys = useMemo(
    () => Object.keys(handlers || {}).sort().join("|"),
    [handlers]
  );

  useEffect(() => {
    handlersRef.current = handlers || {};
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

    const bindCustomHandlers = () => {
      Object.entries(handlersRef.current || {}).forEach(([event, handler]) => {
        if (typeof handler !== "function") return;
        socket.off(event);
        socket.on(event, handler);
      });
    };

    const unbindCustomHandlers = () => {
      Object.entries(handlersRef.current || {}).forEach(([event, handler]) => {
        if (typeof handler !== "function") return;
        socket.off(event, handler);
      });
    };

    const handleConnect = () => {
      setConnectionStatus("connected");
      setLastConnectedAt(new Date().toISOString());
      setLastError("");
      bindCustomHandlers();
    };

    const handleDisconnect = (reason) => {
      setConnectionStatus("disconnected");
      setLastDisconnectedAt(new Date().toISOString());

      if (reason) {
        setLastError(String(reason));
      }
    };

    const handleConnectError = (error) => {
      setConnectionStatus("error");
      setLastError(error?.message || "Socket connection error");
    };

    socket.on("connect", handleConnect);
    socket.on("disconnect", handleDisconnect);
    socket.on("connect_error", handleConnectError);

    bindCustomHandlers();

    if (!socket.connected) {
      socket.connect();
    }

    return () => {
      unbindCustomHandlers();

      socket.off("connect", handleConnect);
      socket.off("disconnect", handleDisconnect);
      socket.off("connect_error", handleConnectError);

      socket.disconnect();
      socketRef.current = null;
    };
  }, [token, handlerKeys]);

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