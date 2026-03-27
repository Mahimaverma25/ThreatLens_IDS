"""
config.py - Configuration for ThreatLens IDS Engine
"""
import os

class Config:
    # Flask server
    HOST = os.environ.get("IDS_ENGINE_HOST", "0.0.0.0")
    PORT = int(os.environ.get("IDS_ENGINE_PORT", 5001))
    DEBUG = os.environ.get("IDS_ENGINE_DEBUG", "false").lower() == "true"

    # Model and detection
    MODEL_PATH = os.environ.get("IDS_ENGINE_MODEL_PATH", "models/attack_model.pkl")
    ENABLE_ANOMALY_DETECTION = os.environ.get("IDS_ENGINE_ENABLE_ANOMALY", "true").lower() == "true"

    # Logging
    LOG_LEVEL = os.environ.get("IDS_ENGINE_LOG_LEVEL", "INFO")
    LOG_FILE = os.environ.get("IDS_ENGINE_LOG_FILE", "ids-engine.log")

    # Simulation
    MAX_SIM_SAMPLES = int(os.environ.get("IDS_ENGINE_MAX_SIM_SAMPLES", 50))

    # Security (if you want to add API keys, etc.)
    API_KEY = os.environ.get("IDS_ENGINE_API_KEY")

config = Config()
