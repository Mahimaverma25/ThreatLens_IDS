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

let isRefreshing = false;
let failedQueue = [];

// 🔁 Process queue after refresh
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
    console.log("✅ API Response:", response.config.url, response.data);
    return response; 
  },
  async (error) => {
    const originalRequest = error.config;

    // Normalize error for frontend
    const normalizedError = {
      message:
        error.response?.data?.message ||
        error.message ||
        "An unknown error occurred",
      status: error.response?.status,
      data: error.response?.data,
    };

    console.error("❌ API Error:", {
      url: originalRequest?.url,
      ...normalizedError,
    });

    // 🚫 Skip auth endpoints
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url.includes("/auth/login") &&
      !originalRequest.url.includes("/auth/refresh")
    ) {
      if (isRefreshing) {
        // ⏳ Queue requests while refreshing
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

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // 🔥 IMPORTANT: use plain axios to avoid interceptor loop
        const refreshRes = await axios.post(
          `${api.defaults.baseURL}/auth/refresh`,
          {},
          { withCredentials: true }
        );

        const newToken = refreshRes.data.token;

        localStorage.setItem("accessToken", newToken);

        processQueue(null, newToken);

        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);

      } catch (refreshError) {
        processQueue(refreshError, null);

        localStorage.removeItem("accessToken");
        window.location.href = "/login";

        return Promise.reject(refreshError);

      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(normalizedError);
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