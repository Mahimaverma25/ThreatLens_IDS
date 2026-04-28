import hmac
import hashlib
import time
import json

from flask import Blueprint, jsonify, request

from config import config
from detector.pipeline import detect_event, detect_batch
from detector.anomaly import get_model_status
from utils.logger import get_logger

logger = get_logger("ids-engine.api")

api_bp = Blueprint("ids_api", __name__)


# ---------- SECURITY ----------

def _verify_request():
    if not config.API_KEY:
        return None

    api_key = request.headers.get("X-API-Key", "")
    timestamp = request.headers.get("X-Timestamp", "")
    signature = request.headers.get("X-Signature", "")

    # API Key check
    if not hmac.compare_digest(api_key, config.API_KEY):
        return jsonify({"message": "Unauthorized: Invalid API Key"}), 401

    # Timestamp check (prevent replay attacks)
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:
            return jsonify({"message": "Request expired"}), 401
    except Exception:
        return jsonify({"message": "Invalid timestamp"}), 400

    # Signature check
    try:
        body = request.get_data(as_text=True)
        expected_signature = _generate_signature(body, timestamp)

        if not hmac.compare_digest(signature, expected_signature):
            return jsonify({"message": "Invalid signature"}), 401

    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return jsonify({"message": "Signature error"}), 400

    return None


def _generate_signature(body: str, timestamp: str) -> str:
    message = f"{timestamp}.{body}".encode()

    secret = hashlib.sha256(config.API_SECRET.encode()).digest()

    return hmac.new(secret, message, hashlib.sha256).hexdigest()


# ---------- HEALTH ----------

@api_bp.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "ThreatLens IDS Engine",
        "model": get_model_status()
    })


# ---------- SINGLE EVENT DETECTION ----------

@api_bp.post("/detect")
def detect():
    auth_error = _verify_request()
    if auth_error:
        return auth_error

    event = request.get_json(silent=True)

    if not isinstance(event, dict):
        return jsonify({"message": "Invalid event format"}), 400

    try:
        result = detect_event(event)

        return jsonify({
            "status": "ok",
            "result": result
        })

    except Exception as e:
        logger.error(f"Detection failed: {e}")
        return jsonify({"message": "Detection error"}), 500


# ---------- BATCH DETECTION ----------

@api_bp.post("/detect/batch")
def detect_batch_route():
    auth_error = _verify_request()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    events = payload.get("events")

    if not isinstance(events, list) or not events:
        return jsonify({"message": "events array is required"}), 400

    if len(events) > config.MAX_BATCH_SIZE:
        return jsonify({
            "message": f"Maximum batch size is {config.MAX_BATCH_SIZE}"
        }), 413

    try:
        results = detect_batch(events)

        return jsonify({
            "status": "ok",
            "count": len(results),
            "results": results
        })

    except Exception as e:
        logger.error(f"Batch detection failed: {e}")
        return jsonify({"message": "Batch processing error"}), 500


# ---------- MODEL STATUS ----------

@api_bp.get("/model/status")
def model_status():
    return jsonify({
        "status": "ok",
        "model": get_model_status()
    })


# ---------- LEGACY SUPPORT (OLD ROUTE) ----------

@api_bp.post("/analyze")
def analyze_legacy():
    """
    Backward compatibility for old code
    """
    auth_error = _verify_request()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    events = payload.get("events")

    if not isinstance(events, list) or not events:
        return jsonify({"message": "events array is required"}), 400

    results = detect_batch(events)

    return jsonify({
        "status": "ok",
        "results": results,
        "model": get_model_status()
    })