def _evaluate_sample(sample):
    alerts = []
    packets = sample.get("packets", 0)
    port = sample.get("port", 0)
    protocol = sample.get("protocol", "TCP")
    bytes_sent = sample.get("bytes", 0)
    request_rate = sample.get("request_rate", 0)
    failed_attempts = sample.get("failed_attempts", 0)
    flow_count = sample.get("flow_count", sample.get("flowCount", 0))
    unique_ports = sample.get("unique_ports", 0)
    dns_queries = sample.get("dns_queries", 0)
    smb_writes = sample.get("smb_writes", 0)

    if packets > 320 or request_rate > 240:
        alerts.append({
            "type": "Possible DDoS Attack",
            "ip": sample["ip"],
            "severity": "Critical",
            "protocol": protocol,
            "destination_port": port,
            "request_rate": request_rate,
            "confidence": 0.92,
            "risk_score": 90
        })

    if port == 22 and (packets > 100 or failed_attempts >= 6):
        alerts.append({
            "type": "Brute Force SSH Attempt",
            "ip": sample["ip"],
            "severity": "Medium",
            "protocol": sample.get("protocol", "SSH"),
            "destination_port": port,
            "failed_attempts": failed_attempts,
            "confidence": 0.72,
            "risk_score": 63
        })

    if unique_ports >= 12 or (flow_count >= 18 and packets >= 140):
        alerts.append({
            "type": "Port Scan Activity",
            "ip": sample["ip"],
            "severity": "High",
            "protocol": protocol,
            "destination_port": port,
            "flow_count": flow_count,
            "unique_ports": unique_ports,
            "confidence": 0.83,
            "risk_score": 77
        })

    if protocol in ["HTTP", "HTTPS"] and failed_attempts >= 7 and request_rate >= 90:
        alerts.append({
            "type": "Credential Stuffing Attempt",
            "ip": sample["ip"],
            "severity": "High",
            "protocol": protocol,
            "destination_port": port,
            "failed_attempts": failed_attempts,
            "request_rate": request_rate,
            "confidence": 0.86,
            "risk_score": 79
        })

    if protocol == "UDP" and port == 53 and dns_queries >= 80:
        alerts.append({
            "type": "DNS Amplification Pattern",
            "ip": sample["ip"],
            "severity": "High",
            "protocol": protocol,
            "destination_port": port,
            "dns_queries": dns_queries,
            "confidence": 0.81,
            "risk_score": 75
        })

    if bytes_sent >= 90000 and flow_count >= 14:
        alerts.append({
            "type": "Potential Data Exfiltration",
            "ip": sample["ip"],
            "severity": "Critical",
            "protocol": protocol,
            "destination_port": port,
            "bytes": bytes_sent,
            "flow_count": flow_count,
            "confidence": 0.89,
            "risk_score": 87
        })

    if port == 445 and smb_writes >= 25:
        alerts.append({
            "type": "Suspicious SMB Lateral Movement",
            "ip": sample["ip"],
            "severity": "High",
            "protocol": protocol,
            "destination_port": port,
            "smb_writes": smb_writes,
            "confidence": 0.8,
            "risk_score": 76
        })

    if protocol in ["HTTP", "HTTPS"] and port in [80, 443, 8080] and failed_attempts >= 4 and request_rate >= 70:
        alerts.append({
            "type": "Web Exploitation / SQLi Probe",
            "ip": sample["ip"],
            "severity": "High",
            "protocol": protocol,
            "destination_port": port,
            "failed_attempts": failed_attempts,
            "confidence": 0.8,
            "risk_score": 74
        })

    if port in [21, 23, 3389, 6379]:
        alerts.append({
            "type": "Sensitive Service Exposure",
            "ip": sample["ip"],
            "severity": "High" if port != 23 else "Critical",
            "protocol": protocol,
            "destination_port": port,
            "confidence": 0.78,
            "risk_score": 72 if port != 23 else 86
        })

    if protocol == "UDP" and port == 53 and dns_queries >= 110:
        alerts.append({
            "type": "DNS Tunneling / Covert Channel",
            "ip": sample["ip"],
            "severity": "High",
            "protocol": protocol,
            "destination_port": port,
            "dns_queries": dns_queries,
            "confidence": 0.84,
            "risk_score": 79
        })

    return alerts


def detect_attack(traffic):
    if isinstance(traffic, list):
        alerts = []
        for sample in traffic:
            alerts.extend(_evaluate_sample(sample))
        return alerts

    return _evaluate_sample(traffic)
