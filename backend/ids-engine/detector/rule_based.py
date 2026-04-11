def _evaluate_sample(sample):
    alerts = []

    if sample["packets"] > 300:
        alerts.append({
            "type": "Possible DDoS Attack",
            "ip": sample["ip"],
            "severity": "High",
            "protocol": sample.get("protocol", "TCP"),
            "destination_port": sample["port"],
            "request_rate": sample.get("request_rate", 0),
            "confidence": 0.88,
            "risk_score": 81
        })

    if sample["port"] == 22 and sample["packets"] > 100:
        alerts.append({
            "type": "Brute Force SSH Attempt",
            "ip": sample["ip"],
            "severity": "Medium",
            "protocol": sample.get("protocol", "SSH"),
            "destination_port": sample["port"],
            "failed_attempts": sample.get("failed_attempts", 0),
            "confidence": 0.72,
            "risk_score": 63
        })

    return alerts


def detect_attack(traffic):
    if isinstance(traffic, list):
        alerts = []
        for sample in traffic:
            alerts.extend(_evaluate_sample(sample))
        return alerts

    return _evaluate_sample(traffic)
