import { useEffect, useRef } from "react";
import { io } from "socket.io-client";

const apiBase = process.env.REACT_APP_API_URL || "http://localhost:5000";
const SOCKET_URL = apiBase.replace(/\/api\/?$/, "");

const useSocket = (token, handlers = {}) => {
  const socketRef = useRef(null);
  const handlersRef = useRef(handlers);

  useEffect(() => {
    handlersRef.current = handlers;
  }, [handlers]);

  useEffect(() => {
    if (!token) {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      return undefined;
    }

    const socket = io(SOCKET_URL, {
      auth: { token },
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: Infinity,
      timeout: 10000,
    });

    socketRef.current = socket;

    const attachHandlers = () => {
      Object.entries(handlersRef.current || {}).forEach(([event, handler]) => {
        socket.off(event);
        socket.on(event, handler);
      });
    };

    attachHandlers();

    return () => {
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

  return socketRef.current;
};

export default useSocket;
