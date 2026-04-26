import React, { createContext, useState, useEffect } from "react";
import { auth as authApi } from "../services/api";

export const AuthContext = createContext();

const normalizeUserRole = (user) => {
  if (!user) {
    return user;
  }

  const normalizedRole =
    String(user.role || "")
      .toLowerCase()
      .trim() === "user"
      ? "analyst"
      : String(user.role || "")
          .toLowerCase()
          .trim();

  return {
    ...user,
    role: ["admin", "analyst", "viewer"].includes(normalizedRole)
      ? normalizedRole
      : "viewer",
  };
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem("user");
      return saved ? normalizeUserRole(JSON.parse(saved)) : null;
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState(true);

  const updateUser = (nextUser) => {
    const normalizedUser = nextUser ? normalizeUserRole(nextUser) : null;

    setUser(normalizedUser);

    if (normalizedUser) {
      localStorage.setItem("user", JSON.stringify(normalizedUser));
    } else {
      localStorage.removeItem("user");
    }
  };

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
        const normalizedUser = normalizeUserRole(meRes.data.user || meRes.data.data);
        updateUser(normalizedUser);
      } catch (err) {
        try {
          const refreshRes = await authApi.refresh();

          const newToken = refreshRes.data.token;
          localStorage.setItem("accessToken", newToken);

          const meRes = await authApi.me();
          const normalizedUser = normalizeUserRole(meRes.data.user || meRes.data.data);
          updateUser(normalizedUser);
        } catch (refreshErr) {
          localStorage.removeItem("accessToken");
          localStorage.removeItem("user");
          updateUser(null);
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

    const { token } = res.data;
    const user = normalizeUserRole(res.data.user);

    localStorage.setItem("accessToken", token);
    updateUser(user);

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
    updateUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        register,
        logout,
        updateUser,
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
