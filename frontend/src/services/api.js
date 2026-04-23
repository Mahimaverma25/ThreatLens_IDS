import axios from "axios";
import {
  getActiveApiBaseUrl,
  getNextApiBaseUrl,
  setActiveApiBaseUrl,
} from "./connection";

const api = axios.create({
  baseURL: getActiveApiBaseUrl(),
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

const bootstrapToken = () => {
  const token = getToken();
  if (token) {
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
  }
};

bootstrapToken();

/* ================= REQUEST INTERCEPTOR ================= */

api.interceptors.request.use((config) => {
  const token = getToken();

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

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
    return response;
  },

  async (error) => {
    const originalRequest = error.config;

    if (!originalRequest) {
      return Promise.reject(error);
    }

    if (!error.response) {
      const nextBaseUrl = getNextApiBaseUrl(
        originalRequest.baseURL || api.defaults.baseURL
      );

      if (
        nextBaseUrl &&
        !originalRequest._localFailoverTried &&
        typeof window !== "undefined"
      ) {
        originalRequest._localFailoverTried = true;
        originalRequest.baseURL = setActiveApiBaseUrl(nextBaseUrl);
        api.defaults.baseURL = originalRequest.baseURL;

        return api(originalRequest);
      }

      return Promise.reject(error);
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
        const refreshRes = await api.post(
          "/auth/refresh",
          {}
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
        localStorage.removeItem("user");

        // clean logout redirect for protected routes only
        if (typeof window !== "undefined") {
          const currentPath = window.location.pathname;
          if (!["/login", "/register"].includes(currentPath)) {
            window.location.href = "/login";
          }
        }

        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
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

export const intel = {
  threatIntel: () => api.get("/intel/threat-intel"),
  threatMap: () => api.get("/intel/threat-map"),
  modelHealth: () => api.get("/intel/model-health"),
  watchlist: () => api.get("/intel/watchlist"),
  createIndicator: (payload) => api.post("/intel/watchlist", payload),
  deleteIndicator: (id) => api.delete(`/intel/watchlist/${id}`),
};

export const incidents = {
  list: (filters = {}) => api.get("/incidents", { params: filters }),
  get: (id) => api.get(`/incidents/${id}`),
  update: (id, payload) => api.patch(`/incidents/${id}`, payload),
};

export const rules = {
  list: (filters = {}) => api.get("/rules", { params: filters }),
  create: (payload) => api.post("/rules", payload),
  update: (id, payload) => api.patch(`/rules/${id}`, payload),
  remove: (id) => api.delete(`/rules/${id}`),
};

export const playbooks = {
  list: () => api.get("/playbooks"),
  execute: (payload) => api.post("/playbooks/execute", payload),
};

export const reports = {
  summary: () => api.get("/reports"),
  exportAlertsCsv: (severity = "") =>
    api.get("/reports/export/alerts.csv", {
      params: severity ? { severity } : {},
      responseType: "blob",
    }),
  exportLogsCsv: () =>
    api.get("/reports/export/logs.csv", {
      responseType: "blob",
    }),
};

export const assets = {
  list: () => api.get("/assets"),
  get: (id) => api.get(`/assets/${id}`),
  create: (payload) => api.post("/assets", payload),
  update: (id, payload) => api.patch(`/assets/${id}`, payload),
  remove: (id) => api.delete(`/assets/${id}`)
};

export const agents = {
  register: (payload) => api.post("/agents/register", payload),
  heartbeats: () => api.get("/agents/heartbeats"),
};

export const users = {
  list: () => api.get("/users"),
  me: () => api.get("/users/me")
};

export const apiKeys = {
  list: () => api.get("/admin/api-keys"),
  create: (payload) => api.post("/admin/api-keys", payload),
  revoke: (id) => api.delete(`/admin/api-keys/${id}`),
  rotate: (id, payload = {}) => api.post(`/admin/api-keys/${id}/rotate`, payload)
};

export default api;
