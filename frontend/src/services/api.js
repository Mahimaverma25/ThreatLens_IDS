import axios from "axios";

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "http://localhost:5000/api",
  timeout: 10000,
  withCredentials: true,
});

/* ================= REQUEST INTERCEPTOR ================= */

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("accessToken");

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  // 🔍 DEBUG LOG
  console.log("📤 API Request:", {
    url: config.url,
    method: config.method,
    data: config.data,
  });

  return config;
});

/* ================= RESPONSE INTERCEPTOR ================= */

api.interceptors.response.use(
  (response) => {
    // 🔍 DEBUG SUCCESS
    console.log("✅ API Response:", response.config.url, response.data);
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // 🔥 DEBUG ERROR (IMPORTANT)
    console.error("❌ API Error:", {
      url: originalRequest?.url,
      status: error.response?.status,
      data: error.response?.data,
    });

    // 🔁 HANDLE TOKEN REFRESH
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url.includes("/auth/login")
    ) {
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

/* ================= AUTH APIs ================= */

export const auth = {
  register: (email, password, username) =>
    api.post("/auth/register", {
      email: email.trim(),
      password: password.trim(),
      username,
    }),

  login: (email, password) => {
    const payload = {
      email: email.trim(),
      password: password.trim(),
    };

    console.log("🔐 Login Payload:", payload);

    return api.post("/auth/login", payload);
  },

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

  simulate: (count = 10) =>
    api.post(`/logs/simulate?count=${count}`),

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