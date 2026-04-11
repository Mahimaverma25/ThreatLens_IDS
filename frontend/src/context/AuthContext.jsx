import React, { createContext, useState, useEffect } from "react";
import { auth as authApi } from "../services/api";

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem("user");
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState(true);

  /* ================= INIT AUTH ================= */

  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem("accessToken");

      if (!token) {
        localStorage.removeItem("user");
        setLoading(false);
        return;
      }

      try {
        const meRes = await authApi.me();
        setUser(meRes.data.user);
        localStorage.setItem("user", JSON.stringify(meRes.data.user));
      } catch (err) {
        try {
          const refreshRes = await authApi.refresh();

          const newToken = refreshRes.data.token;
          localStorage.setItem("accessToken", newToken);

          const meRes = await authApi.me();
          setUser(meRes.data.user);
          localStorage.setItem("user", JSON.stringify(meRes.data.user));
        } catch (refreshErr) {
          localStorage.removeItem("accessToken");
          localStorage.removeItem("user");
          setUser(null);
        }
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  /* ================= LOGIN ================= */

  const login = async (email, password) => {
    const res = await authApi.login(email, password);

    const { token, user } = res.data;

    localStorage.setItem("accessToken", token);
    localStorage.setItem("user", JSON.stringify(user));
    setUser(user);

    return res.data;
  };

  /* ================= REGISTER ================= */

  const register = async (email, password, username) => {
    const res = await authApi.register(email, password, username);
    return res.data;
  };

  /* ================= LOGOUT ================= */

  const logout = async () => {
    try {
      await authApi.logout();
    } catch (err) {
      console.log("Logout API failed (ignored)");
    }

    localStorage.removeItem("accessToken");
    localStorage.removeItem("user");
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

/* ================= HOOK ================= */

export const useAuth = () => {
  const context = React.useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }

  return context;
};