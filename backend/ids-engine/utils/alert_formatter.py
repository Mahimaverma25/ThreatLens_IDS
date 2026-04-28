from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _severity_rank(severity: str) -> int:
    ranks = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return ranks.get(str(severity).lower(), 1)


def normalize_severity(severity: str, confidence: float = 0.0) -> str:
    severity = str(severity or "low").lower()

    if severity in {"critical", "high", "medium", "low"}:
        return severity

    if confidence >= 0.90:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.50:
        return "medium"

    return "low"


def build_alert(
    event: Dict[str, Any],
    result: Dict[str, Any],
    engines: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Converts pipeline detection output into a backend/dashboard-ready alert object.
    """

    confidence = _safe_float(result.get("confidence"), 0.0)
    severity = normalize_severity(result.get("severity"), confidence)

    is_attack = bool(result.get("is_attack", False))

    alert_type = result.get("attack_type") or "benign"
    detection_type = result.get("detection_type") or "none"

    src_ip = event.get("src_ip") or event.get("source_ip") or "unknown"
    dest_ip = event.get("dest_ip") or event.get("dst_ip") or event.get("destination_ip") or "unknown"

    src_port = event.get("src_port") or event.get("source_port") or 0
    dest_port = event.get("dest_port") or event.get("destination_port") or event.get("port") or 0

    return {
        "alert_id": f"tl-{int(datetime.now(timezone.utc).timestamp() * 1000)}",

        "timestamp": event.get("timestamp") or _now_iso(),
        "created_at": _now_iso(),

        "is_attack": is_attack,
        "status": "open" if is_attack else "benign",

        "attack_type": alert_type,
        "severity": severity,
        "confidence": confidence,
        "detection_type": detection_type,

        "title": build_alert_title(alert_type, severity, is_attack),
        "description": result.get("reason") or "ThreatLens detection pipeline generated this event.",

        "network": {
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": int(_safe_float(src_port, 0)),
            "dest_port": int(_safe_float(dest_port, 0)),
            "protocol": str(event.get("protocol", "UNKNOWN")).upper(),
        },

        "source": {
            "event_type": event.get("event_type", "network_event"),
            "source": event.get("source", "ids-engine"),
            "is_snort": bool(_safe_float(event.get("is_snort"), 0)),
            "snort_priority": _safe_float(event.get("snort_priority"), 0),
            "raw_log": event.get("raw_log"),
        },

        "metrics": {
            "request_rate": _safe_float(event.get("request_rate"), 0),
            "packets": _safe_float(event.get("packets"), 0),
            "bytes": _safe_float(event.get("bytes"), 0),
            "failed_attempts": _safe_float(event.get("failed_attempts"), 0),
            "flow_count": _safe_float(event.get("flow_count"), 0),
            "unique_ports": _safe_float(event.get("unique_ports"), 0),
            "dns_queries": _safe_float(event.get("dns_queries"), 0),
            "smb_writes": _safe_float(event.get("smb_writes"), 0),
            "duration": _safe_float(event.get("duration"), 0),
        },

        "engines": engines or {},

        "recommended_action": recommend_action(alert_type, severity, is_attack),
    }


def build_alert_from_pipeline(pipeline_output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts full detect_event() response and returns formatted alert.
    """

    event = pipeline_output.get("event", {})
    result = pipeline_output.get("result", {})
    engines = pipeline_output.get("engines", {})

    return build_alert(event, result, engines)


def build_alert_title(attack_type: str, severity: str, is_attack: bool) -> str:
    if not is_attack:
        return "Benign network event"

    attack_name = str(attack_type or "Suspicious Activity").replace("_", " ").title()
    severity_name = str(severity or "medium").upper()

    return f"{severity_name} {attack_name} Detected"


def recommend_action(attack_type: str, severity: str, is_attack: bool) -> str:
    if not is_attack:
        return "No immediate action required. Continue monitoring."

    attack = str(attack_type or "").lower()
    severity = str(severity or "medium").lower()

    if "brute" in attack or "failed" in attack:
        return "Review authentication logs, block repeated source IPs, and enforce account lockout or MFA."

    if "ddos" in attack or "dos" in attack or "flood" in attack:
        return "Rate-limit traffic, block attacking sources, and check network bandwidth/utilization."

    if "scan" in attack or "port" in attack:
        return "Investigate source IP, review firewall logs, and block scanning hosts if unauthorized."

    if "sql" in attack or "xss" in attack or "web" in attack:
        return "Inspect web server logs, validate input filtering, and review WAF/application rules."

    if "dns" in attack:
        return "Review DNS query patterns, block suspicious domains, and inspect possible tunneling behavior."

    if "smb" in attack or "lateral" in attack:
        return "Check SMB activity, isolate affected host if needed, and review file share permissions."

    if "exfil" in attack:
        return "Investigate outbound data transfer, isolate affected endpoint, and review user/process activity."

    if severity == "critical":
        return "Escalate immediately, isolate affected asset, preserve logs, and begin incident response."

    if severity == "high":
        return "Investigate promptly, verify related logs, and apply containment if confirmed."

    return "Review the event, correlate with recent activity, and monitor for repeated behavior."