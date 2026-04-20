import logging
import os


def get_logger(name: str = "ids-engine") -> logging.Logger:
	level_name = os.getenv("IDS_ENGINE_LOG_LEVEL", os.getenv("LOG_LEVEL", "INFO")).upper()
	level = getattr(logging, level_name, logging.INFO)

	logger = logging.getLogger(name)
	if logger.handlers:
		return logger

	logger.setLevel(level)
	formatter = logging.Formatter(
		"%(asctime)s %(levelname)s %(name)s - %(message)s"
	)

	handler = logging.StreamHandler()
	handler.setFormatter(formatter)
	logger.addHandler(handler)
	logger.propagate = False

	return logger
