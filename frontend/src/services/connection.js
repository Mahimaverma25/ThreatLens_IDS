const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1"]);
const LOCAL_API_CANDIDATE_PORTS = [5000, 5001, 5002, 5003, 5004, 5005];

export const trimTrailingSlashes = (value = "") => String(value).replace(/\/+$/, "");

const isLocalHostname = (hostname = "") => LOCALHOST_HOSTS.has(String(hostname).trim().toLowerCase());

const getWindowOrigin = () =>
  typeof window !== "undefined" ? window.location.origin : "http://localhost:3000";

const normalizeApiBaseUrl = (value) => trimTrailingSlashes(value);

const resolveConfiguredApiBaseUrl = () => {
  const configuredBaseUrl = (process.env.REACT_APP_API_URL || "").trim();

  if (!configuredBaseUrl) {
    if (typeof window !== "undefined") {
      const appHostname = window.location.hostname || "localhost";
      if (isLocalHostname(appHostname)) {
        return `http://${appHostname}:5000/api`;
      }
    }

    return "/api";
  }

  if (typeof window === "undefined") {
    return normalizeApiBaseUrl(configuredBaseUrl);
  }

  try {
    const resolvedUrl = new URL(configuredBaseUrl, getWindowOrigin());
    const appHostname = window.location.hostname;

    if (isLocalHostname(resolvedUrl.hostname) && !isLocalHostname(appHostname)) {
      return "/api";
    }

    return normalizeApiBaseUrl(resolvedUrl.toString());
  } catch {
    return normalizeApiBaseUrl(configuredBaseUrl);
  }
};

const buildLocalApiBaseCandidates = (configuredApiBaseUrl) => {
  if (typeof window === "undefined") {
    return [];
  }

  const candidates = [];
  const pushCandidate = (value) => {
    const normalized = normalizeApiBaseUrl(value);
    if (normalized && !candidates.includes(normalized)) {
      candidates.push(normalized);
    }
  };

  try {
    const appUrl = new URL(getWindowOrigin());
    const configuredUrl = new URL(configuredApiBaseUrl, getWindowOrigin());
    const localConfigured =
      configuredApiBaseUrl === "/api" ||
      (isLocalHostname(appUrl.hostname) && isLocalHostname(configuredUrl.hostname));

    if (localConfigured) {
      const protocol = configuredUrl.protocol || appUrl.protocol || "http:";
      const hostname = configuredUrl.hostname || appUrl.hostname || "localhost";

      LOCAL_API_CANDIDATE_PORTS.forEach((port) => {
        pushCandidate(`${protocol}//${hostname}:${port}/api`);
      });
    }
  } catch {
    // Ignore URL parsing problems and fall back to the configured candidate below.
  }

  pushCandidate(configuredApiBaseUrl);

  return candidates;
};

const configuredApiBaseUrl = resolveConfiguredApiBaseUrl();
const apiBaseCandidates = buildLocalApiBaseCandidates(configuredApiBaseUrl);

let activeApiBaseUrl = configuredApiBaseUrl;

export const getConfiguredApiBaseUrl = () => configuredApiBaseUrl;

export const getApiBaseCandidates = () => [...apiBaseCandidates];

export const getActiveApiBaseUrl = () => activeApiBaseUrl;

export const setActiveApiBaseUrl = (value) => {
  activeApiBaseUrl = normalizeApiBaseUrl(value);
  return activeApiBaseUrl;
};

export const getNextApiBaseUrl = (currentBaseUrl) => {
  const candidates = getApiBaseCandidates();
  if (candidates.length <= 1) {
    return null;
  }

  const normalizedCurrent = normalizeApiBaseUrl(currentBaseUrl || activeApiBaseUrl);
  const currentIndex = candidates.indexOf(normalizedCurrent);

  if (currentIndex === -1) {
    return candidates[0] === normalizedCurrent ? null : candidates[0];
  }

  return candidates[currentIndex + 1] || null;
};

export const resolveSocketUrlFromApiBase = (apiBaseUrl) =>
  normalizeApiBaseUrl(String(apiBaseUrl || configuredApiBaseUrl).replace(/\/api\/?$/, ""));

export const getActiveSocketUrl = () => resolveSocketUrlFromApiBase(activeApiBaseUrl);
