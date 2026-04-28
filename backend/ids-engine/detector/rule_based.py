from typing import Any, Dict, List

from utils.logger import get_logger

logger = get_logger("ids-engine.rule-based")


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    return int(_safe_float(value, default))


def _normalize_protocol(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


def _normalize_severity(value: str) -> str:
    value = str(value or "low").lower()

    if value in {"critical", "high", "medium", "low"}:
        return value

    return "low"


def _get_source_ip(sample: Dict[str, Any]) -> str:
    return (
        sample.get("src_ip")
        or sample.get("source_ip")
        or sample.get("sourceIp")
        or sample.get("ip")
        or "unknown"
    )


def _get_destination_ip(sample: Dict[str, Any]) -> str:
    return (
        sample.get("dest_ip")
        or sample.get("dst_ip")
        or sample.get("destination_ip")
        or sample.get("destinationIp")
        or "unknown"
    )


def _get_destination_port(sample: Dict[str, Any]) -> int:
    return _safe_int(
        sample.get(
            "dest_port",
            sample.get("destination_port", sample.get("port", 0)),
        )
    )


def _make_alert(
    sample: Dict[str, Any],
    attack_type: str,
    severity: str,
    confidence: float,
    risk_score: int,
    reason: str,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    extra = extra or {}

    return {
        "engine": "rule_based",
        "is_attack": True,
        "attack": True,
        "attack_type": attack_type,
        "type": attack_type,
        "severity": _normalize_severity(severity),
        "confidence": round(float(confidence), 4),
        "risk_score": int(risk_score),
        "reason": reason,
        "src_ip": _get_source_ip(sample),
        "dest_ip": _get_destination_ip(sample),
        "protocol": _normalize_protocol(sample.get("protocol")),
        "destination_port": _get_destination_port(sample),
        "raw": {
            **extra,
        },
    }


def _evaluate_sample(sample: Dict[str, Any]) -> List[Dict[str, Any]]:
    sample = sample or {}

    alerts: List[Dict[str, Any]] = []

    packets = _safe_float(sample.get("packets"), 0)
    port = _get_destination_port(sample)
    protocol = _normalize_protocol(sample.get("protocol", "TCP"))

    bytes_sent = _safe_float(sample.get("bytes"), 0)
    request_rate = _safe_float(sample.get("request_rate"), 0)
    failed_attempts = _safe_float(sample.get("failed_attempts"), 0)
    flow_count = _safe_float(sample.get("flow_count", sample.get("flowCount", 0)))
    unique_ports = _safe_float(sample.get("unique_ports", sample.get("uniquePorts", 0)))
    dns_queries = _safe_float(sample.get("dns_queries", sample.get("dnsQueries", 0)))
    smb_writes = _safe_float(sample.get("smb_writes", sample.get("smbWrites", 0)))
    snort_priority = _safe_float(sample.get("snort_priority", sample.get("priority", 0)))
    attack_type = str(sample.get("attack_type") or sample.get("signature") or "").lower()

    if snort_priority == 1:
        alerts.append(
            _make_alert(
                sample,
                "Critical Snort Signature Alert",
                "critical",
                0.95,
                92,
                "Snort generated a priority 1 alert.",
                {"snort_priority": snort_priority},
            )
        )

    elif snort_priority == 2:
        alerts.append(
            _make_alert(
                sample,
                "High Priority Snort Signature Alert",
                "high",
                0.88,
                82,
                "Snort generated a priority 2 alert.",
                {"snort_priority": snort_priority},
            )
        )

    if "sql" in attack_type or "xss" in attack_type:
        alerts.append(
            _make_alert(
                sample,
                "Web Exploitation Signature Detected",
                "high",
                0.90,
                84,
                "Snort or parser detected a web exploitation signature.",
                {"attack_type": attack_type},
            )
        )

    if packets > 320 or request_rate > 240:
        alerts.append(
            _make_alert(
                sample,
                "Possible DDoS Attack",
                "critical",
                0.92,
                90,
                "Packet volume or request rate exceeded DDoS threshold.",
                {
                    "packets": packets,
                    "request_rate": request_rate,
                },
            )
        )

    if port == 22 and (packets > 100 or failed_attempts >= 6):
        alerts.append(
            _make_alert(
                sample,
                "Brute Force SSH Attempt",
                "medium",
                0.72,
                63,
                "Multiple SSH attempts or high packet count detected on port 22.",
                {
                    "packets": packets,
                    "failed_attempts": failed_attempts,
                },
            )
        )

    if unique_ports >= 12 or (flow_count >= 18 and packets >= 140):
        alerts.append(
            _make_alert(
                sample,
                "Port Scan Activity",
                "high",
                0.83,
                77,
                "Traffic touched many unique ports or created many flows.",
                {
                    "flow_count": flow_count,
                    "unique_ports": unique_ports,
                    "packets": packets,
                },
            )
        )

    if protocol in {"HTTP", "HTTPS", "TCP"} and port in {80, 443, 8080} and failed_attempts >= 7 and request_rate >= 90:
        alerts.append(
            _make_alert(
                sample,
                "Credential Stuffing Attempt",
                "high",
                0.86,
                79,
                "High failed attempts with elevated web request rate detected.",
                {
                    "failed_attempts": failed_attempts,
                    "request_rate": request_rate,
                },
            )
        )

    if protocol == "UDP" and port == 53 and dns_queries >= 80:
        alerts.append(
            _make_alert(
                sample,
                "DNS Amplification Pattern",
                "high",
                0.81,
                75,
                "High DNS query volume detected over UDP port 53.",
                {
                    "dns_queries": dns_queries,
                },
            )
        )

    if protocol == "UDP" and port == 53 and dns_queries >= 110:
        alerts.append(
            _make_alert(
                sample,
                "DNS Tunneling / Covert Channel",
                "high",
                0.84,
                79,
                "Very high DNS query count may indicate tunneling or covert communication.",
                {
                    "dns_queries": dns_queries,
                },
            )
        )

    if bytes_sent >= 90000 and flow_count >= 14:
        alerts.append(
            _make_alert(
                sample,
                "Potential Data Exfiltration",
                "critical",
                0.89,
                87,
                "Large outbound data volume with many flows detected.",
                {
                    "bytes": bytes_sent,
                    "flow_count": flow_count,
                },
            )
        )

    if port == 445 and smb_writes >= 25:
        alerts.append(
            _make_alert(
                sample,
                "Suspicious SMB Lateral Movement",
                "high",
                0.80,
                76,
                "High SMB write activity detected on port 445.",
                {
                    "smb_writes": smb_writes,
                },
            )
        )

    if protocol in {"HTTP", "HTTPS", "TCP"} and port in {80, 443, 8080} and failed_attempts >= 4 and request_rate >= 70:
        alerts.append(
            _make_alert(
                sample,
                "Web Exploitation / SQLi Probe",
                "high",
                0.80,
                74,
                "Suspicious web probing behavior detected.",
                {
                    "failed_attempts": failed_attempts,
                    "request_rate": request_rate,
                },
            )
        )

    if port in {21, 23, 3389, 6379}:
        alerts.append(
            _make_alert(
                sample,
                "Sensitive Service Exposure",
                "critical" if port == 23 else "high",
                0.78,
                86 if port == 23 else 72,
                "Traffic detected on a sensitive or risky exposed service port.",
                {
                    "port": port,
                },
            )
        )

    return alerts


def _pick_best_alert(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not alerts:
        return {
            "engine": "rule_based",
            "is_attack": False,
            "attack": False,
            "attack_type": "benign",
            "type": "benign",
            "severity": "low",
            "confidence": 0.0,
            "risk_score": 0,
            "reason": "No rule matched this event.",
            "alerts": [],
        }

    severity_rank = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    best = max(
        alerts,
        key=lambda alert: (
            severity_rank.get(alert.get("severity", "low"), 1),
            alert.get("risk_score", 0),
            alert.get("confidence", 0),
        ),
    )

    return {
        **best,
        "alerts": alerts,
        "matched_rules": len(alerts),
    }


def detect_rule_based(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pipeline-compatible rule-based detection function.

    Used by:
        detector/pipeline.py
    """

    try:
        alerts = _evaluate_sample(event or {})
        return _pick_best_alert(alerts)

    except Exception as exc:
        logger.exception("Rule-based detection failed")

        return {
            "engine": "rule_based",
            "is_attack": False,
            "attack": False,
            "attack_type": "processing_error",
            "type": "processing_error",
            "severity": "low",
            "confidence": 0.0,
            "risk_score": 0,
            "reason": str(exc),
            "alerts": [],
        }


def detect_attack(traffic):
    """
    Backward-compatible function for old code.
    Returns list of alerts like your previous version.
    """

    if isinstance(traffic, list):
        alerts = []

        for sample in traffic:
            alerts.extend(_evaluate_sample(sample))

        return alerts

    return _evaluate_sample(traffic or {})