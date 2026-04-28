import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

LOG_DIR = os.getenv("IDS_ENGINE_LOG_DIR", "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def get_logger(name: str = "ids-engine") -> logging.Logger:
    level_name = os.getenv("IDS_ENGINE_LOG_LEVEL", os.getenv("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)

    # ---------- FORMAT ----------
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    # ---------- CONSOLE HANDLER ----------
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # ---------- FILE HANDLER (ALL LOGS) ----------
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "ids_engine.log"),
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    # ---------- ERROR FILE HANDLER ----------
    error_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "errors.log"),
        maxBytes=2 * 1024 * 1024,
        backupCount=3
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)

    # ---------- ADD HANDLERS ----------
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)

    logger.propagate = False

    return logger