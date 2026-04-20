import os
from typing import Dict, List, Tuple

import joblib
import numpy as np

from config import config
from utils.logger import get_logger

logger = get_logger("ids-engine.anomaly")

FEATURE_NAMES = [
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

PROTOCOL_CODES = {
    "TCP": 1,
    "UDP": 2,
    "ICMP": 3,
    "HTTP": 4,
    "HTTPS": 5,
    "SSH": 6,
    "DNS": 7,
    "FTP": 8,
    "SMTP": 9,
    "POP3": 10,
    "IMAP": 11,
    "TELNET": 12,
    "RDP": 13,
    "SMB": 14,
    "LDAP": 15,
    "NTP": 16,
    "MYSQL": 17,
    "POSTGRES": 18,
}


def _as_float(value, fallback: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _protocol_code(value: str) -> int:
    return PROTOCOL_CODES.get(str(value or "").upper(), 0)


def _infer_protocol_from_port(port: float) -> int:
    port_map = {
        21: PROTOCOL_CODES["FTP"],
        22: PROTOCOL_CODES["SSH"],
        23: PROTOCOL_CODES["TELNET"],
        25: PROTOCOL_CODES["SMTP"],
        53: PROTOCOL_CODES["DNS"],
        80: PROTOCOL_CODES["HTTP"],
        88: PROTOCOL_CODES["LDAP"],
        110: PROTOCOL_CODES["POP3"],
        123: PROTOCOL_CODES["NTP"],
        143: PROTOCOL_CODES["IMAP"],
        389: PROTOCOL_CODES["LDAP"],
        443: PROTOCOL_CODES["HTTPS"],
        445: PROTOCOL_CODES["SMB"],
        3389: PROTOCOL_CODES["RDP"],
        3306: PROTOCOL_CODES["MYSQL"],
        5432: PROTOCOL_CODES["POSTGRES"],
        8080: PROTOCOL_CODES["HTTP"],
        8443: PROTOCOL_CODES["HTTPS"],
    }
    return port_map.get(int(port or 0), 0)


def normalize_event(event: Dict) -> Dict:
    protocol = event.get("protocol") or event.get("app_protocol") or ""
    destination_port = _as_float(event.get("destination_port", event.get("port", 0)))
    protocol_code = _as_float(event.get("protocol_code", _protocol_code(protocol)))

    if protocol_code == 0 and destination_port:
        protocol_code = float(_infer_protocol_from_port(destination_port))

    return {
        "protocol_code": protocol_code,
        "destination_port": destination_port,
        "request_rate": _as_float(event.get("request_rate")),
        "packets": _as_float(event.get("packets")),
        "bytes": _as_float(event.get("bytes")),
        "failed_attempts": _as_float(event.get("failed_attempts")),
        "flow_count": _as_float(event.get("flow_count", event.get("flowCount", 0))),
        "unique_ports": _as_float(event.get("unique_ports", event.get("uniquePorts", 0))),
        "dns_queries": _as_float(event.get("dns_queries", event.get("dnsQueries", 0))),
        "smb_writes": _as_float(event.get("smb_writes", event.get("smbWrites", 0))),
        "duration": _as_float(event.get("duration")),
        "snort_priority": _as_float(event.get("snort_priority", 0)),
        "is_snort": _as_float(event.get("is_snort", 0)),
    }


def _feature_matrix(normalized_event: Dict) -> np.ndarray:
    return np.array([[normalized_event.get(name, 0.0) for name in FEATURE_NAMES]], dtype=float)


def _load_artifact(model_path: str):
    if not config.ENABLE_ANOMALY_DETECTION:
        return {
            "loaded": False,
            "algorithm": None,
            "task": "fallback",
            "using_fallback": True,
            "threshold": 0.65,
            "model": None,
            "feature_names": FEATURE_NAMES,
            "trained_at": None,
            "error": "Anomaly detection disabled by configuration",
        }

    if not os.path.exists(model_path):
        logger.warning("Model file missing: %s", model_path)
        return {
            "loaded": False,
            "algorithm": None,
            "task": "fallback",
            "using_fallback": True,
            "threshold": 0.65,
            "model": None,
            "feature_names": FEATURE_NAMES,
            "trained_at": None,
            "error": f"Model file missing: {model_path}",
        }

    try:
        artifact = joblib.load(model_path)
        model = artifact.get("model") if isinstance(artifact, dict) else artifact
        feature_names = artifact.get("feature_names", FEATURE_NAMES) if isinstance(artifact, dict) else FEATURE_NAMES
        threshold = float(artifact.get("threshold", 0.65)) if isinstance(artifact, dict) else 0.65
        algorithm = artifact.get("algorithm", type(model).__name__) if isinstance(artifact, dict) else type(model).__name__
        trained_at = artifact.get("trained_at") if isinstance(artifact, dict) else None
        task = artifact.get("task", "anomaly") if isinstance(artifact, dict) else "anomaly"

        return {
            "loaded": True,
            "algorithm": algorithm,
            "task": task,
            "using_fallback": False,
            "threshold": threshold,
            "model": model,
            "feature_names": feature_names,
            "trained_at": trained_at,
            "error": None,
        }
    except Exception as exc:  # pragma: no cover
        logger.error("Failed to load model: %s", exc)
        return {
            "loaded": False,
            "algorithm": None,
            "task": "fallback",
            "using_fallback": True,
            "threshold": 0.65,
            "model": None,
            "feature_names": FEATURE_NAMES,
            "trained_at": None,
            "error": str(exc),
        }


MODEL_STATE = _load_artifact(config.MODEL_PATH)


def get_model_status() -> Dict:
    return {
        "loaded": MODEL_STATE["loaded"],
        "algorithm": MODEL_STATE["algorithm"],
        "task": MODEL_STATE.get("task", "anomaly"),
        "using_fallback": MODEL_STATE["using_fallback"],
        "threshold": MODEL_STATE["threshold"],
        "trained_at": MODEL_STATE["trained_at"],
        "model_path": config.MODEL_PATH,
        "feature_names": MODEL_STATE["feature_names"],
        "error": MODEL_STATE["error"],
    }


def _fallback_score(normalized_event: Dict) -> Tuple[float, str]:
    request_rate = min(normalized_event["request_rate"] / 180.0, 1.0)
    packets = min(normalized_event["packets"] / 400.0, 1.0)
    bytes_sent = min(normalized_event["bytes"] / 90000.0, 1.0)
    failed_attempts = min(normalized_event["failed_attempts"] / 8.0, 1.0)
    flow_count = min(normalized_event["flow_count"] / 20.0, 1.0)
    unique_ports = min(normalized_event["unique_ports"] / 15.0, 1.0)
    dns_queries = min(normalized_event["dns_queries"] / 100.0, 1.0)
    smb_writes = min(normalized_event["smb_writes"] / 30.0, 1.0)
    snort_weight = 1.0 if normalized_event["snort_priority"] > 0 else 0.0
    high_snort_priority = 1.0 if 0 < normalized_event["snort_priority"] <= 2 else 0.0

    score = (
        (request_rate * 0.18)
        + (packets * 0.14)
        + (bytes_sent * 0.14)
        + (failed_attempts * 0.14)
        + (flow_count * 0.1)
        + (unique_ports * 0.1)
        + (dns_queries * 0.08)
        + (smb_writes * 0.08)
        + (snort_weight * 0.08)
        + (high_snort_priority * 0.06)
    )

    score = round(min(max(score, 0.0), 1.0), 4)

    if score >= 0.78:
        return score, "High-volume network behavior exceeded fallback thresholds"
    if score >= 0.65:
        return score, "Multiple elevated traffic indicators triggered the fallback detector"
    return score, "Traffic stayed within the fallback baseline"


def _model_score(normalized_event: Dict) -> Tuple[float, str]:
    if not MODEL_STATE["loaded"] or MODEL_STATE["model"] is None:
        return _fallback_score(normalized_event)

    matrix = _feature_matrix(normalized_event)
    task = MODEL_STATE.get("task", "anomaly")

    if task == "classification" and hasattr(MODEL_STATE["model"], "predict_proba"):
        probabilities = MODEL_STATE["model"].predict_proba(matrix)[0]
        positive_index = 1 if len(probabilities) > 1 else 0
        score = float(probabilities[positive_index])
        if score >= MODEL_STATE["threshold"]:
            return score, "Supervised model probability crossed the learned malicious threshold"
        return score, "Supervised model probability stayed inside the benign range"

    score = -float(MODEL_STATE["model"].decision_function(matrix)[0])
    if score >= MODEL_STATE["threshold"]:
        return score, "IsolationForest score crossed the learned anomaly threshold"
    return score, "IsolationForest score stayed inside the learned baseline"


def _build_severity(score: float, threshold: float) -> Tuple[bool, str, float, int]:
    if score < threshold:
        confidence = max(0.2, min(0.7, threshold - score + 0.2))
        return False, "Low", round(confidence, 4), int(min(45, confidence * 60))

    distance = max(score - threshold, 0.0)
    confidence = round(min(0.98, 0.7 + distance * 1.4), 4)

    if score >= threshold + 0.25:
        return True, "Critical", confidence, min(96, int(80 + distance * 100))
    if score >= threshold + 0.15:
        return True, "High", confidence, min(88, int(72 + distance * 90))
    return True, "Medium", confidence, min(75, int(60 + distance * 80))


def analyze_event(event: Dict) -> Dict:
    normalized = normalize_event(event or {})
    score, reason = _model_score(normalized)
    threshold = float(MODEL_STATE["threshold"])

    if MODEL_STATE["using_fallback"]:
        score = round(score, 4)
        threshold = 0.65

    is_anomaly, severity, confidence, risk_score = _build_severity(score, threshold)

    return {
        "algorithm": MODEL_STATE["algorithm"] or "heuristic-fallback",
        "task": MODEL_STATE.get("task", "fallback"),
        "using_fallback": MODEL_STATE["using_fallback"],
        "is_anomaly": is_anomaly,
        "score": round(score, 4),
        "threshold": threshold,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "reason": reason,
        "features": normalized,
    }


def analyze_events(events: List[Dict]) -> List[Dict]:
    return [
        {
            "event_id": event.get("event_id"),
            "analysis": analyze_event(event),
        }
        for event in events
    ]
