from datetime import datetime, timezone
from typing import Any, Dict, Optional

from detector.rule_based import detect_rule_based
from detector.anomaly import detect_anomaly
from utils.logger import get_logger

logger = get_logger("ids-engine.pipeline")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts incoming Snort / agent / uploaded CSV event data into one common format.
    """

    normalized = {
        "timestamp": event.get("timestamp") or _now_iso(),

        "src_ip": event.get("src_ip") or event.get("source_ip") or event.get("sourceIp"),
        "dest_ip": event.get("dest_ip") or event.get("dst_ip") or event.get("destination_ip") or event.get("destinationIp"),

        "src_port": int(_safe_float(event.get("src_port") or event.get("source_port"), 0)),
        "dest_port": int(_safe_float(event.get("dest_port") or event.get("destination_port") or event.get("port"), 0)),

        "protocol": str(event.get("protocol", "UNKNOWN")).upper(),

        "event_type": event.get("event_type") or event.get("type") or "network_event",

        "attack_type": event.get("attack_type") or event.get("signature") or event.get("message"),
        "severity": str(event.get("severity", "low")).lower(),

        "request_rate": _safe_float(event.get("request_rate"), 0),
        "packets": _safe_float(event.get("packets"), 0),
        "bytes": _safe_float(event.get("bytes"), 0),
        "failed_attempts": _safe_float(event.get("failed_attempts"), 0),
        "flow_count": _safe_float(event.get("flow_count") or event.get("flowCount"), 0),
        "unique_ports": _safe_float(event.get("unique_ports") or event.get("uniquePorts"), 0),
        "dns_queries": _safe_float(event.get("dns_queries") or event.get("dnsQueries"), 0),
        "smb_writes": _safe_float(event.get("smb_writes") or event.get("smbWrites"), 0),
        "duration": _safe_float(event.get("duration"), 0),

        "snort_priority": _safe_float(event.get("snort_priority") or event.get("priority"), 0),
        "is_snort": 1.0 if event.get("is_snort") or event.get("signature_id") or event.get("sid") else 0.0,

        "raw_log": event.get("raw_log"),
        "source": event.get("source", "ids-engine"),
    }

    return normalized


def _default_result(engine: str) -> Dict[str, Any]:
    return {
        "engine": engine,
        "is_attack": False,
        "attack_type": "benign",
        "severity": "low",
        "confidence": 0.0,
        "reason": "No suspicious behavior detected",
    }


def _safe_rule_detection(event: Dict[str, Any]) -> Dict[str, Any]:
    try:
        result = detect_rule_based(event)

        if not isinstance(result, dict):
            return _default_result("rule_based")

        return {
            "engine": "rule_based",
            "is_attack": bool(result.get("is_attack", result.get("attack", False))),
            "attack_type": result.get("attack_type") or result.get("type") or "rule_detected",
            "severity": result.get("severity", "medium"),
            "confidence": _safe_float(result.get("confidence", result.get("score", 0.75)), 0.75),
            "reason": result.get("reason", "Matched rule-based detection logic"),
            "raw": result,
        }

    except Exception as exc:
        logger.exception("Rule-based detection failed: %s", exc)
        return {
            **_default_result("rule_based"),
            "error": str(exc),
        }


def _safe_ml_detection(event: Dict[str, Any]) -> Dict[str, Any]:
    try:
        result = detect_anomaly(event)

        if not isinstance(result, dict):
            return _default_result("ml_anomaly")

        return {
            "engine": "ml_anomaly",
            "is_attack": bool(result.get("is_attack", result.get("anomaly", False))),
            "attack_type": result.get("attack_type") or result.get("prediction") or "ml_anomaly",
            "severity": result.get("severity", "medium"),
            "confidence": _safe_float(result.get("confidence", result.get("score", 0.0)), 0.0),
            "reason": result.get("reason", "ML model detected abnormal behavior"),
            "raw": result,
        }

    except Exception as exc:
        logger.exception("ML anomaly detection failed: %s", exc)
        return {
            **_default_result("ml_anomaly"),
            "error": str(exc),
        }


def _severity_rank(severity: str) -> int:
    ranks = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return ranks.get(str(severity).lower(), 1)


def _pick_final_result(rule_result: Dict[str, Any], ml_result: Dict[str, Any]) -> Dict[str, Any]:
    rule_attack = bool(rule_result.get("is_attack"))
    ml_attack = bool(ml_result.get("is_attack"))

    if rule_attack and ml_attack:
        stronger = rule_result if _severity_rank(rule_result["severity"]) >= _severity_rank(ml_result["severity"]) else ml_result

        return {
            "is_attack": True,
            "attack_type": stronger.get("attack_type", "hybrid_detection"),
            "severity": stronger.get("severity", "high"),
            "confidence": max(
                _safe_float(rule_result.get("confidence"), 0.0),
                _safe_float(ml_result.get("confidence"), 0.0),
            ),
            "detection_type": "hybrid",
            "reason": "Both rule-based engine and ML engine detected suspicious behavior",
        }

    if rule_attack:
        return {
            "is_attack": True,
            "attack_type": rule_result.get("attack_type", "rule_detected"),
            "severity": rule_result.get("severity", "medium"),
            "confidence": _safe_float(rule_result.get("confidence"), 0.75),
            "detection_type": "rule_based",
            "reason": rule_result.get("reason", "Rule-based engine detected suspicious behavior"),
        }

    if ml_attack:
        return {
            "is_attack": True,
            "attack_type": ml_result.get("attack_type", "ml_anomaly"),
            "severity": ml_result.get("severity", "medium"),
            "confidence": _safe_float(ml_result.get("confidence"), 0.65),
            "detection_type": "machine_learning",
            "reason": ml_result.get("reason", "ML engine detected abnormal behavior"),
        }

    return {
        "is_attack": False,
        "attack_type": "benign",
        "severity": "low",
        "confidence": 0.0,
        "detection_type": "none",
        "reason": "No detection engine marked this event as suspicious",
    }


def detect_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main ThreatLens detection pipeline.

    Flow:
    1. Normalize event
    2. Run rule-based detection
    3. Run ML anomaly detection
    4. Fuse results
    5. Return dashboard/backend-ready alert result
    """

    normalized_event = normalize_event(event)

    rule_result = _safe_rule_detection(normalized_event)
    ml_result = _safe_ml_detection(normalized_event)

    final_result = _pick_final_result(rule_result, ml_result)

    return {
        "timestamp": normalized_event["timestamp"],
        "processed_at": _now_iso(),

        "event": normalized_event,

        "result": final_result,

        "engines": {
            "rule_based": rule_result,
            "machine_learning": ml_result,
        },
    }


def detect_batch(events: list) -> list:
    results = []

    for event in events:
        try:
            results.append(detect_event(event))
        except Exception as exc:
            logger.exception("Pipeline failed for event: %s", exc)
            results.append(
                {
                    "processed_at": _now_iso(),
                    "event": event,
                    "result": {
                        "is_attack": False,
                        "attack_type": "processing_error",
                        "severity": "low",
                        "confidence": 0.0,
                        "detection_type": "error",
                        "reason": str(exc),
                    },
                    "engines": {},
                }
            )

    return results