import math
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
        if value is None or value == "":
            return fallback
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
    event = event or {}

    protocol = event.get("protocol") or event.get("app_protocol") or ""
    destination_port = _as_float(
        event.get(
            "destination_port",
            event.get("dest_port", event.get("port", 0)),
        )
    )

    protocol_code = _as_float(
        event.get("protocol_code", _protocol_code(protocol))
    )

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
        "snort_priority": _as_float(event.get("snort_priority", event.get("priority", 0))),
        "is_snort": _as_float(event.get("is_snort", 1 if event.get("signature_id") or event.get("sid") else 0)),
    }


def _feature_matrix(normalized_event: Dict) -> np.ndarray:
    return np.array(
        [[normalized_event.get(name, 0.0) for name in FEATURE_NAMES]],
        dtype=float,
    )


def _load_artifact(model_path: str, default_task: str) -> Dict:
    default_state = {
        "loaded": False,
        "algorithm": None,
        "task": default_task,
        "using_fallback": True,
        "threshold": 0.65,
        "model": None,
        "feature_names": FEATURE_NAMES,
        "trained_at": None,
        "error": None,
        "path": model_path,
        "training_summary": None,
        "class_names": [],
        "benign_indexes": [],
    }

    if not config.ENABLE_ANOMALY_DETECTION:
        default_state["error"] = "Anomaly detection disabled by configuration"
        return default_state

    if not os.path.exists(model_path):
        default_state["error"] = f"Model file missing: {model_path}"
        return default_state

    try:
        artifact = joblib.load(model_path)

        if isinstance(artifact, dict):
            model = artifact.get("model")
            return {
                **default_state,
                "loaded": model is not None,
                "algorithm": artifact.get("algorithm", type(model).__name__ if model else None),
                "task": artifact.get("task", default_task),
                "using_fallback": False,
                "threshold": float(artifact.get("threshold", 0.65)),
                "model": model,
                "feature_names": artifact.get("feature_names", FEATURE_NAMES),
                "trained_at": artifact.get("trained_at"),
                "training_summary": artifact.get("training_summary"),
                "class_names": artifact.get("class_names", []),
                "benign_indexes": artifact.get("benign_indexes", []),
            }

        return {
            **default_state,
            "loaded": True,
            "algorithm": type(artifact).__name__,
            "using_fallback": False,
            "model": artifact,
        }

    except Exception as exc:
        logger.exception("Failed to load model from %s", model_path)
        default_state["error"] = str(exc)
        return default_state


RF_STATE = _load_artifact(config.RF_MODEL_PATH, "classification")
SVM_STATE = _load_artifact(config.SVM_MODEL_PATH, "anomaly")
LEGACY_STATE = _load_artifact(config.MODEL_PATH, "anomaly")


def get_model_status() -> Dict:
    states = (RF_STATE, SVM_STATE, LEGACY_STATE)

    hybrid_loaded = any(state["loaded"] for state in states)

    algorithms = [
        state["algorithm"]
        for state in states
        if state["loaded"] and state["algorithm"]
    ]

    trained_values = [
        state["trained_at"]
        for state in states
        if state.get("trained_at")
    ]

    loaded_thresholds = [
        state["threshold"]
        for state in states
        if state["loaded"]
    ]

    return {
        "loaded": hybrid_loaded,
        "algorithm": " + ".join(algorithms) if algorithms else "heuristic-fallback",
        "task": "hybrid",
        "using_fallback": not hybrid_loaded,
        "threshold": min(loaded_thresholds or [0.65]),
        "trained_at": max(trained_values) if trained_values else None,
        "feature_names": FEATURE_NAMES,
        "rf_model": {
            "loaded": RF_STATE["loaded"],
            "algorithm": RF_STATE["algorithm"],
            "threshold": RF_STATE["threshold"],
            "trained_at": RF_STATE["trained_at"],
            "path": RF_STATE["path"],
            "error": RF_STATE["error"],
            "training_summary": RF_STATE["training_summary"],
            "class_names": RF_STATE["class_names"],
        },
        "svm_model": {
            "loaded": SVM_STATE["loaded"],
            "algorithm": SVM_STATE["algorithm"],
            "threshold": SVM_STATE["threshold"],
            "trained_at": SVM_STATE["trained_at"],
            "path": SVM_STATE["path"],
            "error": SVM_STATE["error"],
            "training_summary": SVM_STATE["training_summary"],
        },
        "legacy_model": {
            "loaded": LEGACY_STATE["loaded"],
            "algorithm": LEGACY_STATE["algorithm"],
            "threshold": LEGACY_STATE["threshold"],
            "trained_at": LEGACY_STATE["trained_at"],
            "path": LEGACY_STATE["path"],
            "error": LEGACY_STATE["error"],
            "training_summary": LEGACY_STATE["training_summary"],
        },
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
        request_rate * 0.18
        + packets * 0.14
        + bytes_sent * 0.14
        + failed_attempts * 0.14
        + flow_count * 0.10
        + unique_ports * 0.10
        + dns_queries * 0.08
        + smb_writes * 0.08
        + snort_weight * 0.08
        + high_snort_priority * 0.06
    )

    score = round(min(max(score, 0.0), 1.0), 4)

    if score >= 0.78:
        return score, "High-volume network behavior exceeded fallback thresholds"
    if score >= 0.65:
        return score, "Multiple elevated traffic indicators triggered the fallback detector"

    return score, "Traffic stayed within the fallback baseline"


def _probability_from_distance(value: float) -> float:
    value = max(min(value, 60), -60)
    return 1.0 / (1.0 + math.exp(-value))


def _rf_score(normalized_event: Dict) -> Tuple[float, str, str]:
    if not RF_STATE["loaded"] or RF_STATE["model"] is None:
        return 0.0, "RandomForest model unavailable", ""

    try:
        matrix = _feature_matrix(normalized_event)
        probabilities = RF_STATE["model"].predict_proba(matrix)[0]

        class_names = RF_STATE.get("class_names") or []
        benign_indexes = set(RF_STATE.get("benign_indexes") or [])

        predicted_index = int(np.argmax(probabilities))
        predicted_class = (
            class_names[predicted_index]
            if predicted_index < len(class_names)
            else str(predicted_index)
        )

        if benign_indexes:
            benign_probability = float(
                sum(
                    probabilities[index]
                    for index in benign_indexes
                    if index < len(probabilities)
                )
            )
            score = max(0.0, min(1.0, 1.0 - benign_probability))
        else:
            score = float(np.max(probabilities))

        if score >= RF_STATE["threshold"]:
            return (
                round(score, 4),
                f"RandomForest predicted {predicted_class} and crossed the malicious threshold",
                predicted_class,
            )

        return (
            round(score, 4),
            f"RandomForest predicted {predicted_class} within the learned baseline",
            predicted_class,
        )

    except Exception as exc:
        logger.exception("RandomForest scoring failed")
        return 0.0, f"RandomForest scoring failed: {exc}", ""


def _svm_score(normalized_event: Dict) -> Tuple[float, str]:
    if not SVM_STATE["loaded"] or SVM_STATE["model"] is None:
        return 0.0, "SVM model unavailable"

    try:
        matrix = _feature_matrix(normalized_event)
        decision_value = -float(SVM_STATE["model"].decision_function(matrix)[0])
        score = round(_probability_from_distance(decision_value), 4)

        if score >= SVM_STATE["threshold"]:
            return score, "SVM anomaly score crossed the suspicious threshold"

        return score, "SVM anomaly score stayed within the learned boundary"

    except Exception as exc:
        logger.exception("SVM scoring failed")
        return 0.0, f"SVM scoring failed: {exc}"


def _legacy_score(normalized_event: Dict) -> Tuple[float, str]:
    if not LEGACY_STATE["loaded"] or LEGACY_STATE["model"] is None:
        return 0.0, "Legacy anomaly model unavailable"

    try:
        matrix = _feature_matrix(normalized_event)
        score = -float(LEGACY_STATE["model"].decision_function(matrix)[0])
        score = round(min(max(_probability_from_distance(score), 0.0), 1.0), 4)

        if score >= LEGACY_STATE["threshold"]:
            return score, "Legacy anomaly model flagged the event"

        return score, "Legacy anomaly model stayed within baseline"

    except Exception as exc:
        logger.exception("Legacy anomaly scoring failed")
        return 0.0, f"Legacy anomaly scoring failed: {exc}"


def _build_severity(score: float, threshold: float) -> Tuple[bool, str, float, int]:
    if score < threshold:
        confidence = max(0.2, min(0.7, threshold - score + 0.2))
        return False, "low", round(confidence, 4), int(min(45, confidence * 60))

    distance = max(score - threshold, 0.0)
    confidence = round(min(0.98, 0.7 + distance * 1.4), 4)

    if score >= threshold + 0.25:
        return True, "critical", confidence, min(96, int(80 + distance * 100))
    if score >= threshold + 0.15:
        return True, "high", confidence, min(88, int(72 + distance * 90))

    return True, "medium", confidence, min(75, int(60 + distance * 80))


def _attack_type_from_rf_class(rf_class: str, is_anomaly: bool) -> str:
    rf_class = str(rf_class or "").lower().strip()

    if rf_class and rf_class not in {"benign", "normal", "0"}:
        return rf_class

    if is_anomaly:
        return "ml_anomaly"

    return "benign"


def analyze_event(event: Dict) -> Dict:
    normalized = normalize_event(event or {})

    rf_score, rf_reason, rf_class = _rf_score(normalized)
    svm_score, svm_reason = _svm_score(normalized)
    legacy_score, legacy_reason = _legacy_score(normalized)

    models_loaded = RF_STATE["loaded"] or SVM_STATE["loaded"] or LEGACY_STATE["loaded"]

    if models_loaded:
        combined_score = max(rf_score, svm_score, legacy_score)

        threshold = min(
            [
                state["threshold"]
                for state in (RF_STATE, SVM_STATE, LEGACY_STATE)
                if state["loaded"]
            ]
            or [0.55]
        )

        reason = " | ".join(
            message
            for message in [rf_reason, svm_reason, legacy_reason]
            if "unavailable" not in message.lower()
        ) or "Hybrid models evaluated the event"
    else:
        combined_score, reason = _fallback_score(normalized)
        threshold = 0.65

    is_anomaly, severity, confidence, risk_score = _build_severity(
        combined_score,
        threshold,
    )

    attack_type = _attack_type_from_rf_class(rf_class, is_anomaly)

    return {
        "algorithm": get_model_status()["algorithm"],
        "task": "hybrid",
        "using_fallback": not models_loaded,
        "is_anomaly": is_anomaly,
        "is_attack": is_anomaly,
        "attack_type": attack_type,
        "prediction": attack_type,
        "score": round(combined_score, 4),
        "threshold": threshold,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "reason": reason,
        "features": normalized,
        "submodels": {
            "random_forest": {
                "loaded": RF_STATE["loaded"],
                "score": round(rf_score, 4),
                "threshold": RF_STATE["threshold"],
                "reason": rf_reason,
                "predicted_class": rf_class,
            },
            "svm": {
                "loaded": SVM_STATE["loaded"],
                "score": round(svm_score, 4),
                "threshold": SVM_STATE["threshold"],
                "reason": svm_reason,
            },
            "legacy": {
                "loaded": LEGACY_STATE["loaded"],
                "score": round(legacy_score, 4),
                "threshold": LEGACY_STATE["threshold"],
                "reason": legacy_reason,
            },
        },
    }


def detect_anomaly(event: Dict) -> Dict:
    """
    Pipeline-compatible ML detector used by detector/pipeline.py.
    """

    analysis = analyze_event(event or {})

    return {
        "engine": "ml_anomaly",
        "is_attack": bool(analysis.get("is_attack", False)),
        "is_anomaly": bool(analysis.get("is_anomaly", False)),
        "attack_type": analysis.get("attack_type", "benign"),
        "prediction": analysis.get("prediction", "benign"),
        "severity": analysis.get("severity", "low"),
        "confidence": float(analysis.get("confidence", 0.0)),
        "score": float(analysis.get("score", 0.0)),
        "risk_score": int(analysis.get("risk_score", 0)),
        "threshold": float(analysis.get("threshold", 0.0)),
        "detection_type": "machine_learning",
        "algorithm": analysis.get("algorithm", "hybrid"),
        "using_fallback": bool(analysis.get("using_fallback", False)),
        "reason": analysis.get("reason", "ML anomaly analysis completed"),
        "features": analysis.get("features", {}),
        "submodels": analysis.get("submodels", {}),
        "raw": analysis,
    }


def analyze_events(events: List[Dict]) -> List[Dict]:
    return [
        {
            "event_id": event.get("event_id"),
            "analysis": analyze_event(event),
            "detection": detect_anomaly(event),
        }
        for event in events
    ]