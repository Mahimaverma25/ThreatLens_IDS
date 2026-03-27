from flask import Flask, request, jsonify
from detector.anomaly import detect_anomaly
from detector.rule_based import rule_check

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.json

    anomaly_result = detect_anomaly(data)
    rule_result = rule_check(data)

    result = {
        "anomaly_score": anomaly_result,
        "rule_match": rule_result
    }

    return jsonify(result)