from typing import Dict, List

PROTOCOL_MAP = {
    "TCP": 1,
    "UDP": 2,
    "ICMP": 3,
    "HTTP": 4,
    "HTTPS": 5,
    "SSH": 6,
    "DNS": 7,
}


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def extract_features(event: Dict) -> Dict:
    """
    Converts normalized event into ML feature format
    """

    protocol = str(event.get("protocol", "UNKNOWN")).upper()

    features = {
        "protocol_code": PROTOCOL_MAP.get(protocol, 0),

        "destination_port": _safe_float(event.get("dest_port", 0)),

        "request_rate": _safe_float(event.get("request_rate", 0)),

        "packets": _safe_float(event.get("packets", 0)),

        "bytes": _safe_float(event.get("bytes", 0)),

        "failed_attempts": _safe_float(event.get("failed_attempts", 0)),

        "flow_count": _safe_float(event.get("flow_count", 0)),

        "unique_ports": _safe_float(event.get("unique_ports", 0)),

        "dns_queries": _safe_float(event.get("dns_queries", 0)),

        "smb_writes": _safe_float(event.get("smb_writes", 0)),

        "duration": _safe_float(event.get("duration", 0)),

        "snort_priority": _safe_float(event.get("snort_priority", 0)),

        "is_snort": _safe_float(event.get("is_snort", 0)),
    }

    return features


def features_to_vector(features: Dict) -> List[float]:
    """
    Converts feature dict → ordered list (for ML model input)
    """

    ordered_keys = [
        "protocol_code",
        "destination_port",
        "request_rate",
        "packets",
        "bytes",
        "failed_attempts",
        "flow_count",
        "unique_ports",
        "dns_queries",
        "smb_writes",
        "duration",
        "snort_priority",
        "is_snort",
    ]

    return [features.get(key, 0.0) for key in ordered_keys]