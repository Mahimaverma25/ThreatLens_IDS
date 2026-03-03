import os
from flask import Flask, jsonify, request
from detector.rule_based import detect_attack
from detector.traffic_simulator import generate_traffic
from detector.anomaly import detect_anomaly
from utils.logger import get_logger

app = Flask(__name__)
logger = get_logger("ids-engine.app")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/scan", methods=["GET"])
def scan_network():
    try:
        samples = int(request.args.get("samples", "1"))
    except ValueError:
        samples = 1

    samples = max(1, min(samples, 50))
    traffic = generate_traffic(samples)

    alerts = detect_attack(traffic)
    if isinstance(traffic, list):
        for sample in traffic:
            alerts.extend(detect_anomaly(sample))
    else:
        alerts.extend(detect_anomaly(traffic))

    return jsonify(alerts) 


@app.errorhandler(Exception)
def handle_error(error):
    logger.error("Unhandled error: %s", error)
    return jsonify({"message": "Internal server error"}), 500


if __name__ == "__main__":
    port = int(os.getenv("IDS_ENGINE_PORT", "5001"))
    debug = os.getenv("IDS_ENGINE_DEBUG", "false").lower() == "true"
    app.run(port=port, debug=debug)
