from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
import time

from api.routes import api_bp
from config import config
from utils.logger import get_logger
from models.load_model import load_all_models

app = Flask(__name__)

# ---------- CORS ----------
CORS(app, resources={r"/*": {"origins": "*"}})

logger = get_logger("ids-engine.app")


# ---------- STARTUP ----------
def initialize_app():
    try:
        logger.info("Initializing ThreatLens IDS Engine...")

        # Load ML models
        load_all_models()
        logger.info("ML models loaded successfully")

    except Exception as e:
        logger.error(f"Startup failed: {e}")


initialize_app()


# ---------- REGISTER ROUTES ----------
app.register_blueprint(api_bp, url_prefix="/api")


# ---------- ROOT ----------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "ok",
        "service": "ThreatLens IDS Engine",
        "version": "1.0",

        "endpoints": {
            "health": "/api/health",
            "detect": "/api/detect",
            "detect_batch": "/api/detect/batch",
            "model_status": "/api/model/status"
        }
    })


# ---------- PING ----------
@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({
        "status": "ok",
        "message": "pong",
        "timestamp": int(time.time())
    })


# ---------- FAVICON ----------
@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return "", 204


# ---------- REQUEST LOGGING (VERY USEFUL) ----------
@app.before_request
def log_request():
    logger.info(
        f"{request.method} {request.path} | IP: {request.remote_addr}"
    )


# ---------- ERROR HANDLING ----------
@app.errorhandler(HTTPException)
def handle_http_error(error):
    logger.warning(f"HTTP Error {error.code}: {error.description}")

    return jsonify({
        "status": "error",
        "message": error.description,
        "code": error.code
    }), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.exception("Unhandled server error")

    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500


# ---------- START SERVER ----------
if __name__ == "__main__":
    logger.info(f"Starting IDS Engine on {config.HOST}:{config.PORT}")

    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )