from flask import Blueprint, jsonify, request

from config import config
from detector.anomaly import analyze_events, get_model_status
from detector.rule_based import detect_attack
from detector.traffic_simulator import generate_traffic

api_bp = Blueprint("ids_api", __name__)


def _require_api_key():
    if not config.API_KEY:
        return None

    provided = request.headers.get("x-integration-api-key", "")
    if provided != config.API_KEY:
        return jsonify({"message": "Unauthorized"}), 401

    return None


@api_bp.get("/health")
def health():
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    return jsonify(
        {
            "status": "ok",
            "message": "IDS engine ready",
            "model": get_model_status(),
        }
    )


@api_bp.post("/analyze")
def analyze():
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True) or {}
    events = payload.get("events")

    if not isinstance(events, list) or not events:
        return jsonify({"message": "events array is required"}), 400

    if len(events) > config.MAX_BATCH_SIZE:
        return jsonify({"message": f"Maximum batch size is {config.MAX_BATCH_SIZE}"}), 413

    results = analyze_events(events)
    return jsonify(
        {
            "status": "ok",
            "results": results,
            "model": get_model_status(),
        }
    )


@api_bp.get("/scan")
def scan():
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    if not config.ENABLE_DEMO_SCAN:
        return (
            jsonify(
                {
                    "message": "Synthetic scan route is disabled. Use the live Snort ingest pipeline.",
                }
            ),
            403,
        )

    try:
        samples = int(request.args.get("samples", "1"))
    except ValueError:
        samples = 1

    samples = max(1, min(samples, 50))
    traffic = generate_traffic(samples)
    alerts = detect_attack(traffic)

    events = traffic if isinstance(traffic, list) else [traffic]
    anomaly_results = analyze_events(events)

    return jsonify(
        {
            "status": "ok",
            "data": alerts,
            "analysis": anomaly_results,
            "model": get_model_status(),
        }
    )
