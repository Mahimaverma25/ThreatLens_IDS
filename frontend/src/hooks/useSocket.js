import { useEffect, useRef } from "react";
import { io } from "socket.io-client";

const apiBase = process.env.REACT_APP_API_URL || "http://localhost:5000";
const SOCKET_URL = apiBase.replace(/\/api\/?$/, "");

const useSocket = (token, handlers = {}) => {
  const socketRef = useRef(null);

  useEffect(() => {
    if (!token) {
      return undefined;
    }

    const socket = io(SOCKET_URL, {
      transports: ["websocket"],
      auth: { token }
    });

    socketRef.current = socket;

    Object.entries(handlers).forEach(([event, handler]) => {
      socket.on(event, handler);
    });

    return () => {
      Object.entries(handlers).forEach(([event, handler]) => {
        socket.off(event, handler);
      });
      socket.disconnect();
    };
  }, [token, handlers]);

  return socketRef.current;
};

export default useSocket;
