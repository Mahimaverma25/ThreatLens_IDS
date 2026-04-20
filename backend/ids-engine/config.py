import os


class Config:
    HOST = os.environ.get("IDS_ENGINE_HOST", "0.0.0.0")
    PORT = int(os.environ.get("IDS_ENGINE_PORT", "8000"))
    DEBUG = os.environ.get("IDS_ENGINE_DEBUG", "false").lower() == "true"

    MODEL_PATH = os.environ.get(
        "IDS_ENGINE_MODEL_PATH",
        os.path.join(os.path.dirname(__file__), "models", "attack_model.pkl"),
    )
    ENABLE_ANOMALY_DETECTION = os.environ.get("IDS_ENGINE_ENABLE_ANOMALY", "true").lower() == "true"
    ENABLE_DEMO_SCAN = os.environ.get("IDS_ENGINE_ENABLE_DEMO_SCAN", "false").lower() == "true"
    MAX_BATCH_SIZE = int(os.environ.get("IDS_ENGINE_MAX_BATCH_SIZE", "500"))

    LOG_LEVEL = os.environ.get("IDS_ENGINE_LOG_LEVEL", os.environ.get("LOG_LEVEL", "INFO"))
    API_KEY = os.environ.get("IDS_ENGINE_API_KEY", "")


config = Config()
