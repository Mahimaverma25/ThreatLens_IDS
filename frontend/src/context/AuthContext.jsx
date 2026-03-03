import React, { createContext, useState, useEffect } from "react";
import { auth as authApi } from "../services/api";

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("accessToken");
    if (!token) {
      setLoading(false);
      return;
    }

    authApi
      .me()
      .then((res) => setUser(res.data.user))
      .catch(async () => {
        try {
          const refreshRes = await authApi.refresh();
          localStorage.setItem("accessToken", refreshRes.data.token);
          const meRes = await authApi.me();
          setUser(meRes.data.user);
        } catch (error) {
          localStorage.removeItem("accessToken");
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const login = async (email, password) => {
    const res = await authApi.login(email, password);
    localStorage.setItem("accessToken", res.data.token);
    setUser(res.data.user);
    return res.data;
  };

  const register = async (email, password, username) => {
    const res = await authApi.register(email, password, username);
    return res.data;
  };

  const logout = () => {
    authApi.logout().catch(() => {});
    localStorage.removeItem("accessToken");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
