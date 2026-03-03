import axios from "axios";

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "http://localhost:3000/api",
  timeout: 10000,
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("accessToken");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const refreshRes = await api.post("/auth/refresh");
        const newToken = refreshRes.data.token;
        localStorage.setItem("accessToken", newToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        localStorage.removeItem("accessToken");
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export const auth = {
  register: (email, password, username) =>
    api.post("/auth/register", { email, password, username }),
  login: (email, password) =>
    api.post("/auth/login", { email, password }),
  refresh: () => api.post("/auth/refresh"),
  logout: () => api.post("/auth/logout"),
  me: () => api.get("/auth/me"),
};

export const alerts = {
  list: (limit = 50, page = 1, filters = {}) =>
    api.get("/alerts", { params: { limit, page, ...filters } }),
  get: (id) => api.get(`/alerts/${id}`),
  update: (id, payload) => api.patch(`/alerts/${id}`, payload),
  scan: () => api.post("/alerts/scan"),
};

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
    api.post("/logs/ingest", payload, { headers: { "x-api-key": apiKey } }),
};

export const dashboard = {
  stats: () => api.get("/dashboard/stats"),
  health: () => api.get("/dashboard/health"),
};

export default api;
