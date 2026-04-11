import os
from typing import Dict, List

try:
	import joblib
except ImportError:  # pragma: no cover - optional dependency
	joblib = None

from utils.logger import get_logger

logger = get_logger("ids-engine.anomaly")

MODEL_PATH = os.getenv(
	"IDS_MODEL_PATH",
	os.path.join(os.path.dirname(__file__), "..", "models", "attack_model.pkl")
)


def _load_model():
	if joblib is None:
		logger.warning("joblib not installed; anomaly detection disabled")
		return None

	if not os.path.exists(MODEL_PATH):
		logger.warning("Model file missing: %s", MODEL_PATH)
		return None

	try:
		return joblib.load(MODEL_PATH)
	except Exception as exc:
		logger.error("Failed to load model: %s", exc)
		return None


MODEL = _load_model()


def detect_anomaly(traffic: Dict) -> List[Dict]:
	if MODEL is None:
		return []

	packets = traffic.get("packets", 0)
	port = traffic.get("port", 0)
	features = [[packets, port]]

	try:
		prediction = MODEL.predict(features)
	except Exception as exc:
		logger.error("Model prediction failed: %s", exc)
		return []

	if int(prediction[0]) == 1:
		return [
			{
				"type": "Anomalous Traffic",
				"ip": traffic.get("ip", "unknown"),
				"severity": "High",
				"protocol": traffic.get("protocol", "TCP"),
				"destination_port": traffic.get("port", 0),
				"request_rate": traffic.get("request_rate", 0),
				"confidence": 0.79,
				"risk_score": 74
			}
		]

	return []
