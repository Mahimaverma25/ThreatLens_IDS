import axios from "axios";

const API_BASE_URL =
  process.env.REACT_APP_API_URL || "https://threatlens-api-vav3.onrender.com/api";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  withCredentials: true,
});

export const getToken = () => localStorage.getItem("accessToken");

export const setToken = (token) => {
  if (!token) return;
  localStorage.setItem("accessToken", token);
  api.defaults.headers.common.Authorization = `Bearer ${token}`;
};

export const clearToken = () => {
  localStorage.removeItem("accessToken");
  localStorage.removeItem("user");
  delete api.defaults.headers.common.Authorization;
};

const token = getToken();
if (token) {
  api.defaults.headers.common.Authorization = `Bearer ${token}`;
}

api.interceptors.request.use(
  (config) => {
    const accessToken = getToken();

    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, tokenValue = null) => {
  failedQueue.forEach((request) => {
    if (error) request.reject(error);
    else request.resolve(tokenValue);
  });

  failedQueue = [];
};

const isAuthRoute = (url = "") =>
  url.includes("/auth/login") ||
  url.includes("/auth/register") ||
  url.includes("/auth/refresh");

api.interceptors.response.use(
  (response) => response,

  async (error) => {
    const originalRequest = error.config;

    if (!originalRequest) return Promise.reject(error);

    if (!error.response) {
      console.error(`Backend not reachable at ${API_BASE_URL}`);
      return Promise.reject(error);
    }

    const status = error.response.status;

    if (
      status === 401 &&
      !originalRequest._retry &&
      !isAuthRoute(originalRequest.url)
    ) {
      originalRequest._retry = true;

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({
            resolve: (newToken) => {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              resolve(api(originalRequest));
            },
            reject,
          });
        });
      }

      isRefreshing = true;

      try {
        const refreshResponse = await api.post("/auth/refresh");

        const newToken =
          refreshResponse.data?.token ||
          refreshResponse.data?.accessToken ||
          refreshResponse.data?.data?.token ||
          refreshResponse.data?.data?.accessToken;

        if (!newToken) {
          throw new Error("Refresh token did not return access token");
        }

        setToken(newToken);
        processQueue(null, newToken);

        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        clearToken();

        if (!["/login", "/register"].includes(window.location.pathname)) {
          window.location.href = "/login";
        }

        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

/* ================= AUTH ================= */

export const auth = {
  register: (email, password, username, role) =>
    api.post("/auth/register", {
      email: email.trim(),
      password: password.trim(),
      username,
      role,
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

/* ================= DASHBOARD ================= */

export const dashboard = {
  overview: () => api.get("/dashboard/overview"),
  stats: () => api.get("/dashboard/stats"),
  health: () => api.get("/dashboard/health"),
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

    return api.post("/logs/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },

  ingest: (payload, apiKey) =>
    api.post("/logs/ingest", payload, {
      headers: { "x-api-key": apiKey },
    }),

  simulate: () => api.post("/logs/simulate"),
};

export const uploads = {
  uploadCsv: async (file) => {
    const formData = new FormData();
    formData.append("file", file);

    try {
      return await api.post("/upload/csv", formData, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 45000,
      });
    } catch (error) {
      if (error?.response?.status !== 404) {
        throw error;
      }

      return api.post("/logs/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 45000,
      });
    }
  },
};

/* ================= OTHER MODULES ================= */

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
  remove: (id) => api.delete(`/assets/${id}`),
};

export const agents = {
  register: (payload) => api.post("/agents/register", payload),
  heartbeats: () => api.get("/agents/heartbeats"),
};

export const users = {
  list: () => api.get("/users"),
  me: () => api.get("/users/me"),
};

export const settings = {
  get: () => api.get("/settings"),
  update: (payload) => api.put("/settings", payload),
};

export const apiKeys = {
  list: () => api.get("/admin/api-keys"),
  create: (payload) => api.post("/admin/api-keys", payload),
  revoke: (id) => api.delete(`/admin/api-keys/${id}`),
  rotate: (id, payload = {}) =>
    api.post(`/admin/api-keys/${id}/rotate`, payload),
};

export const playbooks = {
  list: () => api.get("/playbooks"),
  execute: (payload) => api.post("/playbooks/execute", payload),
};

export default api;
