from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from api.routes import api_bp
from config import config
from utils.logger import get_logger

app = Flask(__name__)
CORS(app)
logger = get_logger("ids-engine.app")

app.register_blueprint(api_bp)

@app.route("/", methods=["GET"])
def root():
    return (
        jsonify(
            {
                "status": "ok",
                "message": "ThreatLens IDS engine is running",
                "health": "/health",
                "analyze": "/analyze",
            }
        ),
        200,
    )


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return "", 204

@app.errorhandler(HTTPException)
def handle_http_error(error):
    return jsonify({
        "message": error.description,
        "code": error.code
    }), error.code

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.exception("Unhandled error")
    return jsonify({"message": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
