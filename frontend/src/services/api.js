import axios from "axios";

/* ================= BASE API ================= */

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "http://localhost:5000/api",
  timeout: 10000,
  withCredentials: true,
});

/* ================= TOKEN HELPERS ================= */

const getToken = () => localStorage.getItem("accessToken");

const setToken = (token) => {
  if (token) {
    localStorage.setItem("accessToken", token);
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
  }
};

const clearToken = () => {
  localStorage.removeItem("accessToken");
  delete api.defaults.headers.common.Authorization;
};

/* ================= REQUEST INTERCEPTOR ================= */

api.interceptors.request.use((config) => {
  const token = getToken();

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  console.log("📤 API Request:", config.method?.toUpperCase(), config.url);

  return config;
});

/* ================= RESPONSE INTERCEPTOR ================= */

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => {
    console.log("✅ API:", response.config.url);
    return response;
  },

  async (error) => {
    const originalRequest = error.config;

    if (!originalRequest || !error.response) {
      return Promise.reject({
        message: "Network error",
      });
    }

    const status = error.response.status;

    const isAuthRoute =
      originalRequest.url?.includes("/auth/login") ||
      originalRequest.url?.includes("/auth/register") ||
      originalRequest.url?.includes("/auth/refresh");

    /* ================= HANDLE 401 REFRESH ================= */

    if (status === 401 && !originalRequest._retry && !isAuthRoute) {
      originalRequest._retry = true;

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({
            resolve: (token) => {
              originalRequest.headers.Authorization = `Bearer ${token}`;
              resolve(api(originalRequest));
            },
            reject: (err) => reject(err),
          });
        });
      }

      isRefreshing = true;

      try {
        const refreshRes = await axios.post(
          `${api.defaults.baseURL}/auth/refresh`,
          {},
          { withCredentials: true }
        );

        const newToken = refreshRes.data?.token;

        if (!newToken) throw new Error("Refresh token missing");

        setToken(newToken);

        processQueue(null, newToken);

        originalRequest.headers.Authorization = `Bearer ${newToken}`;

        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);

        clearToken();

        // clean logout
        if (typeof window !== "undefined") {
          window.location.href = "/login";
        }

        return Promise.reject({
          message: "Session expired. Please login again.",
          status: 401,
        });
      } finally {
        isRefreshing = false;
      }
    }

    /* ================= NORMAL ERROR ================= */

    return Promise.reject({
      message:
        error.response?.data?.message ||
        error.message ||
        "Something went wrong",
      status,
      data: error.response?.data,
    });
  }
);

/* ================= AUTH APIs ================= */

export const auth = {
  register: (email, password, username) =>
    api.post("/auth/register", {
      email: email.trim(),
      password: password.trim(),
      username,
    }),

  login: (email, password) =>
    api.post("/auth/login", {
      email: email.trim(),
      password: password.trim(),
    }),

  refresh: () => api.post("/auth/refresh"),

  logout: () => api.post("/auth/logout"),

  me: () => api.get("/auth/me"),
};

/* ================= ALERTS ================= */

export const alerts = {
  list: (limit = 50, page = 1, filters = {}) =>
    api.get("/alerts", { params: { limit, page, ...filters } }),

  get: (id) => api.get(`/alerts/${id}`),

  update: (id, payload) => api.patch(`/alerts/${id}`, payload),

  scan: () => api.post("/alerts/scan"),
};

/* ================= LOGS ================= */

export const logs = {
  list: (limit = 50, page = 1, filters = {}) =>
    api.get("/logs", { params: { limit, page, ...filters } }),

  create: (message, level = "info", source = "frontend", metadata = {}) =>
    api.post("/logs", { message, level, source, metadata }),

  upload: (file) => {
    const formData = new FormData();
    formData.append("file", file);
    return api.post("/logs/upload", formData);
  },

  simulate: (count = 10) => api.post(`/logs/simulate?count=${count}`),

  ingest: (payload, apiKey) =>
    api.post("/logs/ingest", payload, {
      headers: { "x-api-key": apiKey },
    }),
};

/* ================= DASHBOARD ================= */

export const dashboard = {
  stats: () => api.get("/dashboard/stats"),
  health: () => api.get("/dashboard/health"),
};

export default api;