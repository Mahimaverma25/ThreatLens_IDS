import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    # ---------- SERVER ----------
    HOST = os.getenv("IDS_ENGINE_HOST", "0.0.0.0")
    PORT = int(os.getenv("IDS_ENGINE_PORT", "8000"))
    DEBUG = os.getenv("IDS_ENGINE_DEBUG", "false").lower() == "true"

    SERVICE_NAME = "ThreatLens IDS Engine"
    VERSION = "1.0"

    # ---------- MODELS ----------
    MODEL_PATH = os.getenv(
        "IDS_ENGINE_MODEL_PATH",
        str(BASE_DIR / "models" / "attack_model.pkl"),
    )

    RF_MODEL_PATH = os.getenv(
        "IDS_ENGINE_RF_MODEL_PATH",
        str(BASE_DIR / "models" / "rf_model.pkl"),
    )

    SVM_MODEL_PATH = os.getenv(
        "IDS_ENGINE_SVM_MODEL_PATH",
        str(BASE_DIR / "models" / "svm_model.pkl"),
    )

    ENABLE_ANOMALY_DETECTION = (
        os.getenv("IDS_ENGINE_ENABLE_ANOMALY", "true").lower() == "true"
    )

    # ---------- ML SETTINGS ----------
    ML_THRESHOLD = float(os.getenv("IDS_ENGINE_ML_THRESHOLD", "0.6"))
    RF_THRESHOLD = float(os.getenv("IDS_ENGINE_RF_THRESHOLD", "0.55"))
    SVM_THRESHOLD = float(os.getenv("IDS_ENGINE_SVM_THRESHOLD", "0.5"))

    # ---------- PIPELINE ----------
    MAX_BATCH_SIZE = int(os.getenv("IDS_ENGINE_MAX_BATCH_SIZE", "500"))
    STREAM_BATCH_SIZE = int(os.getenv("IDS_ENGINE_STREAM_BATCH_SIZE", "10"))
    STREAM_FLUSH_INTERVAL = int(os.getenv("IDS_ENGINE_STREAM_FLUSH_INTERVAL", "5"))

    # ---------- LOGGING ----------
    LOG_LEVEL = os.getenv(
        "IDS_ENGINE_LOG_LEVEL",
        os.getenv("LOG_LEVEL", "INFO"),
    )

    LOG_DIR = os.getenv(
        "IDS_ENGINE_LOG_DIR",
        str(BASE_DIR / "logs"),
    )

    # ---------- SECURITY ----------
    API_KEY = os.getenv("IDS_ENGINE_API_KEY", "")
    API_SECRET = os.getenv("IDS_ENGINE_API_SECRET", "change-this-secret")

    ENABLE_SIGNATURE_VALIDATION = (
        os.getenv("IDS_ENGINE_ENABLE_SIGNATURE", "true").lower() == "true"
    )

    REQUEST_TIMEOUT_SECONDS = int(
        os.getenv("IDS_ENGINE_REQUEST_TIMEOUT", "5")
    )

    # ---------- BACKEND INTEGRATION ----------
    BACKEND_URL = os.getenv(
        "THREATLENS_BACKEND_URL",
        "http://localhost:5000/api",
    )

    ALERT_ENDPOINT = os.getenv(
        "THREATLENS_ALERT_ENDPOINT",
        f"{BACKEND_URL}/alerts",
    )

    ENABLE_ALERT_FORWARDING = (
        os.getenv("IDS_ENGINE_ENABLE_FORWARDING", "false").lower() == "true"
    )

    # ---------- SNORT / NIDS ----------
    SNORT_LOG_PATH = os.getenv(
        "SNORT_FAST_LOG_PATH",
        "/var/log/snort/alert_fast.txt",
    )

    ENABLE_SNORT = os.getenv("IDS_ENGINE_ENABLE_SNORT", "false").lower() == "true"

    # ---------- RATE LIMIT ----------
    MAX_REQUESTS_PER_MINUTE = int(
        os.getenv("IDS_ENGINE_RATE_LIMIT", "1000")
    )

    # ---------- DEV / TEST ----------
    ENABLE_SIMULATOR = (
        os.getenv("IDS_ENGINE_ENABLE_SIMULATOR", "true").lower() == "true"
    )

    # ---------- VALIDATION ----------
    def validate(self):
        errors = []

        if self.ENABLE_SIGNATURE_VALIDATION and not self.API_SECRET:
            errors.append("API_SECRET is required when signature validation is enabled")

        if self.MAX_BATCH_SIZE <= 0:
            errors.append("MAX_BATCH_SIZE must be > 0")

        if self.PORT <= 0:
            errors.append("Invalid PORT configuration")

        if errors:
            raise ValueError(f"Config validation failed: {errors}")


# ---------- GLOBAL INSTANCE ----------
config = Config()

# Validate at import time (fail fast)
try:
    config.validate()
except Exception as e:
    print(f"[CONFIG ERROR] {e}")