import os


class Config:
    HOST = os.environ.get("IDS_ENGINE_HOST", "0.0.0.0")
    PORT = int(os.environ.get("IDS_ENGINE_PORT", "8000"))
    DEBUG = os.environ.get("IDS_ENGINE_DEBUG", "false").lower() == "true"

    MODEL_PATH = os.environ.get(
        "IDS_ENGINE_MODEL_PATH",
        os.path.join(os.path.dirname(__file__), "models", "attack_model.pkl"),
    )
    RF_MODEL_PATH = os.environ.get(
        "IDS_ENGINE_RF_MODEL_PATH",
        os.path.join(os.path.dirname(__file__), "models", "rf_model.pkl"),
    )
    SVM_MODEL_PATH = os.environ.get(
        "IDS_ENGINE_SVM_MODEL_PATH",
        os.path.join(os.path.dirname(__file__), "models", "svm_model.pkl"),
    )
    ENABLE_ANOMALY_DETECTION = os.environ.get("IDS_ENGINE_ENABLE_ANOMALY", "true").lower() == "true"
    MAX_BATCH_SIZE = int(os.environ.get("IDS_ENGINE_MAX_BATCH_SIZE", "500"))

    LOG_LEVEL = os.environ.get("IDS_ENGINE_LOG_LEVEL", os.environ.get("LOG_LEVEL", "INFO"))
    API_KEY = os.environ.get("IDS_ENGINE_API_KEY", "")


config = Config()
