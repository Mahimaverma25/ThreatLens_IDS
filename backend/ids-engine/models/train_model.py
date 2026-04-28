import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from utils.logger import get_logger

logger = get_logger("ids-engine.train-model")

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_OUTPUT = ROOT / "models" / "attack_model.pkl"
DEFAULT_RF_OUTPUT = ROOT / "models" / "rf_model.pkl"
DEFAULT_SVM_OUTPUT = ROOT / "models" / "svm_model.pkl"
DEFAULT_INPUT = ROOT / "data" / "training_samples.csv"
DEFAULT_METRICS_OUTPUT = ROOT / "models" / "training_metrics.json"

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


def _as_float(value, fallback: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return fallback
        return float(value)
    except (TypeError, ValueError):
        return fallback


def normalize_training_record(record: dict) -> dict:
    return {
        "protocol_code": _as_float(record.get("protocol_code", 0)),
        "destination_port": _as_float(record.get("destination_port", record.get("port", 0))),
        "request_rate": _as_float(record.get("request_rate", 0)),
        "packets": _as_float(record.get("packets", 0)),
        "bytes": _as_float(record.get("bytes", 0)),
        "failed_attempts": _as_float(record.get("failed_attempts", 0)),
        "flow_count": _as_float(record.get("flow_count", record.get("flowCount", 0))),
        "unique_ports": _as_float(record.get("unique_ports", record.get("uniquePorts", 0))),
        "dns_queries": _as_float(record.get("dns_queries", record.get("dnsQueries", 0))),
        "smb_writes": _as_float(record.get("smb_writes", record.get("smbWrites", 0))),
        "duration": _as_float(record.get("duration", 0)),
        "snort_priority": _as_float(record.get("snort_priority", 0)),
        "is_snort": _as_float(record.get("is_snort", 0)),
    }


def _record_label(record: dict):
    for key in ("attack_type", "attack_class", "class_name", "label_name"):
        raw = str(record.get(key, "")).strip()
        if raw:
            return raw.lower().replace(" ", "_")

    raw = str(record.get("label", "")).strip()
    if not raw:
        return None

    try:
        numeric = int(float(raw))
        return "benign" if numeric == 0 else "malicious"
    except ValueError:
        normalized = raw.lower().replace(" ", "_")
        if normalized in {"0", "benign", "normal", "false"}:
            return "benign"
        if normalized in {"1", "attack", "malicious", "anomaly", "true"}:
            return "malicious"
        return normalized


def load_json_lines(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_json(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
        return payload if isinstance(payload, list) else [payload]


def load_csv_rows(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def load_training_records(path: str) -> Tuple[List[dict], List[str]]:
    extension = os.path.splitext(path)[1].lower()

    if extension in {".jsonl", ".ndjson"}:
        rows = list(load_json_lines(path))
    elif extension == ".json":
        rows = list(load_json(path))
    elif extension == ".csv":
        rows = list(load_csv_rows(path))
    else:
        raise ValueError(f"Unsupported training data format: {extension}")

    records = [normalize_training_record(record) for record in rows]
    labels = [_record_label(record) for record in rows]

    resolved_labels = [label for label in labels if label is not None]

    if resolved_labels:
        fallback_label = "benign" if "benign" in resolved_labels else resolved_labels[0]
        labels = [label if label is not None else fallback_label for label in labels]
    else:
        labels = []

    return records, labels


def generate_benign_sample() -> dict:
    protocol_code = np.random.choice(
        [1, 2, 4, 5, 6, 7],
        p=[0.34, 0.16, 0.2, 0.12, 0.08, 0.1],
    )

    destination_port = int(
        np.random.choice(
            [22, 53, 80, 443, 8080, 3306, 5432],
            p=[0.08, 0.1, 0.3, 0.28, 0.1, 0.07, 0.07],
        )
    )

    return {
        "protocol_code": protocol_code,
        "destination_port": destination_port,
        "request_rate": float(np.clip(np.random.normal(42, 16), 1, 120)),
        "packets": float(np.clip(np.random.normal(85, 28), 5, 210)),
        "bytes": float(np.clip(np.random.normal(11000, 6500), 300, 40000)),
        "failed_attempts": float(np.random.poisson(0.5)),
        "flow_count": float(np.clip(np.random.normal(4, 2), 1, 12)),
        "unique_ports": float(np.clip(np.random.normal(2.4, 1.2), 1, 6)),
        "dns_queries": float(np.clip(np.random.normal(4, 3), 0, 18)),
        "smb_writes": 0.0 if destination_port != 445 else float(np.clip(np.random.normal(2, 1), 0, 6)),
        "duration": float(np.clip(np.random.normal(2.1, 1.0), 0.1, 8.0)),
        "snort_priority": 0.0,
        "is_snort": 0.0,
    }


def generate_attack_sample() -> dict:
    profile = np.random.choice(
        ["ddos", "bruteforce", "dns_tunnel", "exfiltration", "smb", "scan", "web"],
        p=[0.16, 0.14, 0.12, 0.14, 0.12, 0.16, 0.16],
    )

    profiles = {
        "ddos": {
            "protocol_code": 4,
            "destination_port": 80,
            "request_rate": np.random.uniform(180, 380),
            "packets": np.random.uniform(260, 520),
            "bytes": np.random.uniform(40000, 90000),
            "failed_attempts": 0,
            "flow_count": np.random.uniform(18, 34),
            "unique_ports": np.random.uniform(4, 8),
            "dns_queries": 0,
            "smb_writes": 0,
            "duration": np.random.uniform(2, 7),
            "snort_priority": 1,
            "is_snort": 1,
        },
        "bruteforce": {
            "protocol_code": 6,
            "destination_port": 22,
            "request_rate": np.random.uniform(60, 140),
            "packets": np.random.uniform(120, 260),
            "bytes": np.random.uniform(12000, 30000),
            "failed_attempts": np.random.uniform(7, 16),
            "flow_count": np.random.uniform(10, 24),
            "unique_ports": np.random.uniform(2, 5),
            "dns_queries": 0,
            "smb_writes": 0,
            "duration": np.random.uniform(4, 12),
            "snort_priority": 2,
            "is_snort": 1,
        },
        "dns_tunnel": {
            "protocol_code": 2,
            "destination_port": 53,
            "request_rate": np.random.uniform(70, 160),
            "packets": np.random.uniform(120, 240),
            "bytes": np.random.uniform(14000, 36000),
            "failed_attempts": 0,
            "flow_count": np.random.uniform(14, 24),
            "unique_ports": np.random.uniform(6, 12),
            "dns_queries": np.random.uniform(80, 160),
            "smb_writes": 0,
            "duration": np.random.uniform(3, 8),
            "snort_priority": 2,
            "is_snort": 1,
        },
        "exfiltration": {
            "protocol_code": 5,
            "destination_port": 443,
            "request_rate": np.random.uniform(40, 90),
            "packets": np.random.uniform(140, 260),
            "bytes": np.random.uniform(90000, 220000),
            "failed_attempts": 0,
            "flow_count": np.random.uniform(14, 30),
            "unique_ports": np.random.uniform(2, 7),
            "dns_queries": 0,
            "smb_writes": 0,
            "duration": np.random.uniform(5, 14),
            "snort_priority": 1,
            "is_snort": 1,
        },
        "smb": {
            "protocol_code": 14,
            "destination_port": 445,
            "request_rate": np.random.uniform(25, 80),
            "packets": np.random.uniform(110, 220),
            "bytes": np.random.uniform(25000, 90000),
            "failed_attempts": 0,
            "flow_count": np.random.uniform(12, 22),
            "unique_ports": np.random.uniform(2, 6),
            "dns_queries": 0,
            "smb_writes": np.random.uniform(24, 48),
            "duration": np.random.uniform(3, 9),
            "snort_priority": 1,
            "is_snort": 1,
        },
        "scan": {
            "protocol_code": 1,
            "destination_port": np.random.choice([21, 22, 23, 80, 443, 445, 3389]),
            "request_rate": np.random.uniform(50, 120),
            "packets": np.random.uniform(90, 200),
            "bytes": np.random.uniform(8000, 24000),
            "failed_attempts": np.random.uniform(0, 3),
            "flow_count": np.random.uniform(16, 30),
            "unique_ports": np.random.uniform(12, 28),
            "dns_queries": 0,
            "smb_writes": 0,
            "duration": np.random.uniform(2, 6),
            "snort_priority": 2,
            "is_snort": 1,
        },
        "web": {
            "protocol_code": 4,
            "destination_port": np.random.choice([80, 443, 8080]),
            "request_rate": np.random.uniform(75, 180),
            "packets": np.random.uniform(110, 260),
            "bytes": np.random.uniform(12000, 60000),
            "failed_attempts": np.random.uniform(4, 12),
            "flow_count": np.random.uniform(10, 20),
            "unique_ports": np.random.uniform(3, 8),
            "dns_queries": 0,
            "smb_writes": 0,
            "duration": np.random.uniform(2, 8),
            "snort_priority": 2,
            "is_snort": 1,
        },
    }

    return {key: float(value) for key, value in profiles[profile].items()}


def build_synthetic_labeled_records(samples: int) -> Tuple[List[dict], List[str]]:
    benign_count = max(int(samples * 0.62), 300)
    attack_count = max(samples - benign_count, 180)

    records = [generate_benign_sample() for _ in range(benign_count)]
    labels = ["benign"] * benign_count

    attack_types = ["malicious"] * attack_count
    records.extend(generate_attack_sample() for _ in range(attack_count))
    labels.extend(attack_types)

    return records, labels


def augment_training_records(records: List[dict], labels: List[str], minimum_samples: int) -> Tuple[List[dict], List[str]]:
    if len(records) >= minimum_samples:
        return records, labels

    synthetic_records, synthetic_labels = build_synthetic_labeled_records(minimum_samples - len(records))
    return records + synthetic_records, labels + synthetic_labels


def build_training_matrix(records: List[dict]) -> np.ndarray:
    return np.array(
        [[record.get(name, 0.0) for name in FEATURE_NAMES] for record in records],
        dtype=float,
    )


def train_supervised_model(matrix: np.ndarray, labels: List[str]):
    label_names = np.array(labels)
    class_names = sorted(set(label_names))

    if len(class_names) < 2:
        raise ValueError("Random Forest requires at least 2 classes.")

    class_to_index = {label: index for index, label in enumerate(class_names)}
    encoded_labels = np.array([class_to_index[label] for label in label_names], dtype=int)

    x_train, x_test, y_train, y_test = train_test_split(
        matrix,
        encoded_labels,
        test_size=0.25,
        random_state=42,
        stratify=encoded_labels,
    )

    model = RandomForestClassifier(
        n_estimators=320,
        max_depth=14,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)
    max_probabilities = probabilities.max(axis=1)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test,
        predictions,
        average="weighted",
        zero_division=0,
    )

    accuracy = accuracy_score(y_test, predictions)

    benign_indexes = [
        index for index, name in enumerate(class_names)
        if name.lower() in {"benign", "normal"}
    ]

    summary = {
        "samples": int(matrix.shape[0]),
        "train_samples": int(x_train.shape[0]),
        "test_samples": int(x_test.shape[0]),
        "features": FEATURE_NAMES,
        "task": "classification",
        "threshold": 0.55,
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "mean_prediction_confidence": float(np.mean(max_probabilities)),
        "class_names": class_names,
        "benign_indexes": benign_indexes,
        "class_balance": {
            name: int((label_names == name).sum()) for name in class_names
        },
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "report": classification_report(
            y_test,
            predictions,
            labels=list(range(len(class_names))),
            target_names=class_names,
            zero_division=0,
        ),
    }

    return model, 0.55, "RandomForestClassifier", summary, class_names, benign_indexes


def train_isolation_forest_model(matrix: np.ndarray, contamination: float):
    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=250,
                    contamination=contamination,
                    random_state=42,
                ),
            ),
        ]
    )

    pipeline.fit(matrix)

    anomaly_scores = -pipeline.decision_function(matrix)
    threshold = max(0.05, float(np.quantile(anomaly_scores, 1 - contamination)))

    summary = {
        "samples": int(matrix.shape[0]),
        "features": FEATURE_NAMES,
        "task": "anomaly",
        "contamination": contamination,
        "threshold": threshold,
        "score_mean": float(np.mean(anomaly_scores)),
        "score_stddev": float(np.std(anomaly_scores)),
    }

    return pipeline, threshold, "IsolationForest", summary


def train_svm_anomaly_model(matrix: np.ndarray):
    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("model", OneClassSVM(kernel="rbf", nu=0.08, gamma="scale")),
        ]
    )

    pipeline.fit(matrix)

    decision_values = -pipeline.decision_function(matrix)
    probabilities = 1.0 / (1.0 + np.exp(-decision_values))
    threshold = float(np.quantile(probabilities, 0.92))

    summary = {
        "samples": int(matrix.shape[0]),
        "features": FEATURE_NAMES,
        "task": "anomaly",
        "threshold": threshold,
        "score_mean": float(np.mean(probabilities)),
        "score_stddev": float(np.std(probabilities)),
    }

    return pipeline, threshold, "OneClassSVM", summary


def save_artifact(path: Path, artifact: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, path)
    logger.info("Model saved: %s", path)


def save_metrics(path: Path, metrics: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    logger.info("Training metrics saved: %s", path)


def main():
    parser = argparse.ArgumentParser(description="Train ThreatLens ML detection models.")

    parser.add_argument("--input", help="Optional path to CSV/JSON/JSONL training data.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="IsolationForest output path.")
    parser.add_argument("--rf-output", default=str(DEFAULT_RF_OUTPUT), help="Random Forest output path.")
    parser.add_argument("--svm-output", default=str(DEFAULT_SVM_OUTPUT), help="One-Class SVM output path.")
    parser.add_argument("--metrics-output", default=str(DEFAULT_METRICS_OUTPUT), help="Training metrics JSON path.")
    parser.add_argument("--samples", type=int, default=2200, help="Minimum training sample count.")
    parser.add_argument("--contamination", type=float, default=0.08, help="Expected anomaly fraction.")

    args = parser.parse_args()

    input_path = args.input

    if not input_path and DEFAULT_INPUT.exists():
        input_path = str(DEFAULT_INPUT)

    if input_path:
        logger.info("Loading training data from %s", input_path)
        records, labels = load_training_records(input_path)
    else:
        logger.warning("No dataset found. Generating synthetic ThreatLens training data.")
        records, labels = build_synthetic_labeled_records(max(args.samples, 600))

    if not records:
        raise ValueError("No training records available.")

    minimum_samples = max(args.samples, 600)
    records, labels = augment_training_records(records, labels, minimum_samples)

    matrix = build_training_matrix(records)
    trained_at = datetime.now(timezone.utc).isoformat()

    logger.info("Training started with %s samples and %s features", matrix.shape[0], matrix.shape[1])

    all_metrics = {
        "trained_at": trained_at,
        "feature_names": FEATURE_NAMES,
        "models": {},
    }

    normalized_labels = [str(label) for label in labels] if labels else []
    use_supervised = bool(normalized_labels) and len(set(normalized_labels)) > 1

    if use_supervised:
        rf_model, rf_threshold, rf_algorithm, rf_summary, class_names, benign_indexes = train_supervised_model(
            matrix,
            normalized_labels,
        )

        rf_artifact = {
            "model": rf_model,
            "feature_names": FEATURE_NAMES,
            "threshold": rf_threshold,
            "algorithm": rf_algorithm,
            "task": "classification",
            "trained_at": trained_at,
            "training_summary": rf_summary,
            "class_names": class_names,
            "benign_indexes": benign_indexes,
        }

        save_artifact(Path(args.rf_output), rf_artifact)
        all_metrics["models"]["random_forest"] = rf_summary

        logger.info("RF accuracy: %.4f", rf_summary["accuracy"])
        logger.info("RF weighted F1: %.4f", rf_summary["f1_score"])
    else:
        logger.warning("Random Forest skipped because labeled classes were not available.")

    svm_model, svm_threshold, svm_algorithm, svm_summary = train_svm_anomaly_model(matrix)

    svm_artifact = {
        "model": svm_model,
        "feature_names": FEATURE_NAMES,
        "threshold": svm_threshold,
        "algorithm": svm_algorithm,
        "task": "anomaly",
        "trained_at": trained_at,
        "training_summary": svm_summary,
    }

    save_artifact(Path(args.svm_output), svm_artifact)
    all_metrics["models"]["one_class_svm"] = svm_summary

    isolation_model, isolation_threshold, isolation_algorithm, isolation_summary = train_isolation_forest_model(
        matrix,
        args.contamination,
    )

    isolation_artifact = {
        "model": isolation_model,
        "feature_names": FEATURE_NAMES,
        "threshold": isolation_threshold,
        "algorithm": isolation_algorithm,
        "task": "anomaly",
        "trained_at": trained_at,
        "training_summary": isolation_summary,
    }

    save_artifact(Path(args.output), isolation_artifact)
    all_metrics["models"]["isolation_forest"] = isolation_summary

    save_metrics(Path(args.metrics_output), all_metrics)

    print("ThreatLens model training completed successfully.")
    print(f"IsolationForest model: {args.output}")
    print(f"One-Class SVM model: {args.svm_output}")

    if use_supervised:
        print(f"Random Forest model: {args.rf_output}")

    print(f"Metrics: {args.metrics_output}")


if __name__ == "__main__":
    main()