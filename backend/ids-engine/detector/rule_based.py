def _evaluate_sample(sample):
    alerts = []

    if sample["packets"] > 300:
        alerts.append({
            "type": "Possible DDoS Attack",
            "ip": sample["ip"],
            "severity": "High"
        })

    if sample["port"] == 22 and sample["packets"] > 100:
        alerts.append({
            "type": "Brute Force SSH Attempt",
            "ip": sample["ip"],
            "severity": "Medium"
        })

    return alerts


def detect_attack(traffic):
    if isinstance(traffic, list):
        alerts = []
        for sample in traffic:
            alerts.extend(_evaluate_sample(sample))
        return alerts

    return _evaluate_sample(traffic)
