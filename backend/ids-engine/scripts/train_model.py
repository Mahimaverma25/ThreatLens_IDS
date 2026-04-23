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

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "models" / "attack_model.pkl"
DEFAULT_RF_OUTPUT = ROOT / "models" / "rf_model.pkl"
DEFAULT_SVM_OUTPUT = ROOT / "models" / "svm_model.pkl"
DEFAULT_INPUT = ROOT / "data" / "training_samples.csv"
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

    if "label" not in record:
        return None
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


def generate_benign_sample() -> dict:
    protocol_code = np.random.choice([1, 2, 4, 5, 6, 7], p=[0.34, 0.16, 0.2, 0.12, 0.08, 0.1])
    destination_port = int(
        np.random.choice([22, 53, 80, 443, 8080, 3306, 5432], p=[0.08, 0.1, 0.3, 0.28, 0.1, 0.07, 0.07])
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
        p=[0.16, 0.14, 0.12, 0.14, 0.12, 0.16, 0.16]
    )

    if profile == "ddos":
        return {
            "protocol_code": 4,
            "destination_port": 80.0,
            "request_rate": float(np.random.uniform(180, 380)),
            "packets": float(np.random.uniform(260, 520)),
            "bytes": float(np.random.uniform(40000, 90000)),
            "failed_attempts": 0.0,
            "flow_count": float(np.random.uniform(18, 34)),
            "unique_ports": float(np.random.uniform(4, 8)),
            "dns_queries": 0.0,
            "smb_writes": 0.0,
            "duration": float(np.random.uniform(2.0, 7.0)),
            "snort_priority": 1.0,
            "is_snort": 1.0,
        }

    if profile == "bruteforce":
        return {
            "protocol_code": 6,
            "destination_port": 22.0,
            "request_rate": float(np.random.uniform(60, 140)),
            "packets": float(np.random.uniform(120, 260)),
            "bytes": float(np.random.uniform(12000, 30000)),
            "failed_attempts": float(np.random.uniform(7, 16)),
            "flow_count": float(np.random.uniform(10, 24)),
            "unique_ports": float(np.random.uniform(2, 5)),
            "dns_queries": 0.0,
            "smb_writes": 0.0,
            "duration": float(np.random.uniform(4.0, 12.0)),
            "snort_priority": 2.0,
            "is_snort": 1.0,
        }

    if profile == "dns_tunnel":
        return {
            "protocol_code": 2,
            "destination_port": 53.0,
            "request_rate": float(np.random.uniform(70, 160)),
            "packets": float(np.random.uniform(120, 240)),
            "bytes": float(np.random.uniform(14000, 36000)),
            "failed_attempts": 0.0,
            "flow_count": float(np.random.uniform(14, 24)),
            "unique_ports": float(np.random.uniform(6, 12)),
            "dns_queries": float(np.random.uniform(80, 160)),
            "smb_writes": 0.0,
            "duration": float(np.random.uniform(3.0, 8.0)),
            "snort_priority": 2.0,
            "is_snort": 1.0,
        }

    if profile == "exfiltration":
        return {
            "protocol_code": 5,
            "destination_port": 443.0,
            "request_rate": float(np.random.uniform(40, 90)),
            "packets": float(np.random.uniform(140, 260)),
            "bytes": float(np.random.uniform(90000, 220000)),
            "failed_attempts": 0.0,
            "flow_count": float(np.random.uniform(14, 30)),
            "unique_ports": float(np.random.uniform(2, 7)),
            "dns_queries": 0.0,
            "smb_writes": 0.0,
            "duration": float(np.random.uniform(5.0, 14.0)),
            "snort_priority": 1.0,
            "is_snort": 1.0,
        }

    if profile == "smb":
        return {
            "protocol_code": 14,
            "destination_port": 445.0,
            "request_rate": float(np.random.uniform(25, 80)),
            "packets": float(np.random.uniform(110, 220)),
            "bytes": float(np.random.uniform(25000, 90000)),
            "failed_attempts": 0.0,
            "flow_count": float(np.random.uniform(12, 22)),
            "unique_ports": float(np.random.uniform(2, 6)),
            "dns_queries": 0.0,
            "smb_writes": float(np.random.uniform(24, 48)),
            "duration": float(np.random.uniform(3.0, 9.0)),
            "snort_priority": 1.0,
            "is_snort": 1.0,
        }

    if profile == "scan":
        return {
            "protocol_code": 1,
            "destination_port": float(np.random.choice([21, 22, 23, 80, 443, 445, 3389])),
            "request_rate": float(np.random.uniform(50, 120)),
            "packets": float(np.random.uniform(90, 200)),
            "bytes": float(np.random.uniform(8000, 24000)),
            "failed_attempts": float(np.random.uniform(0, 3)),
            "flow_count": float(np.random.uniform(16, 30)),
            "unique_ports": float(np.random.uniform(12, 28)),
            "dns_queries": 0.0,
            "smb_writes": 0.0,
            "duration": float(np.random.uniform(2.0, 6.0)),
            "snort_priority": 2.0,
            "is_snort": 1.0,
        }

    return {
        "protocol_code": 4,
        "destination_port": float(np.random.choice([80, 443, 8080])),
        "request_rate": float(np.random.uniform(75, 180)),
        "packets": float(np.random.uniform(110, 260)),
        "bytes": float(np.random.uniform(12000, 60000)),
        "failed_attempts": float(np.random.uniform(4, 12)),
        "flow_count": float(np.random.uniform(10, 20)),
        "unique_ports": float(np.random.uniform(3, 8)),
        "dns_queries": 0.0,
        "smb_writes": 0.0,
        "duration": float(np.random.uniform(2.0, 8.0)),
        "snort_priority": 2.0,
        "is_snort": 1.0,
    }


def build_synthetic_labeled_records(samples: int) -> Tuple[List[dict], List[int]]:
    benign_count = max(int(samples * 0.62), 300)
    attack_count = max(samples - benign_count, 180)

    records = [generate_benign_sample() for _ in range(benign_count)] + [
        generate_attack_sample() for _ in range(attack_count)
    ]
    labels = [0] * benign_count + [1] * attack_count
    return records, labels


def augment_training_records(
    records: List[dict], labels: List[str], minimum_samples: int
) -> Tuple[List[dict], List[str]]:
    if len(records) >= minimum_samples:
        return records, labels

    synthetic_records, synthetic_labels = build_synthetic_labeled_records(
        max(minimum_samples - len(records), 0)
    )
    normalized_synthetic_labels = [
        "benign" if int(label) == 0 else "malicious" for label in synthetic_labels
    ]

    return (
        records + synthetic_records,
        labels + normalized_synthetic_labels if labels else normalized_synthetic_labels,
    )


def load_json_lines(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_json(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
        if isinstance(payload, list):
            return payload
        return [payload]


def load_csv_rows(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def load_training_records(path: str) -> Tuple[List[dict], List[int]]:
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


def build_training_matrix(records: List[dict]) -> np.ndarray:
    return np.array([[record.get(name, 0.0) for name in FEATURE_NAMES] for record in records], dtype=float)


def train_supervised_model(matrix: np.ndarray, labels: List[str]):
    label_names = np.array(labels)
    class_names = sorted({label for label in label_names})
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
        n_jobs=1,
    )
    model.fit(x_train, y_train)

    probabilities = model.predict_proba(x_test)
    max_probabilities = probabilities.max(axis=1)
    predictions = model.predict(x_test)
    threshold = 0.55
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, average="weighted", zero_division=0
    )
    accuracy = accuracy_score(y_test, predictions)
    matrix_output = confusion_matrix(y_test, predictions).tolist()
    benign_indexes = [
        index for index, name in enumerate(class_names) if name.lower() in {"benign", "normal"}
    ]

    summary = {
        "samples": int(matrix.shape[0]),
        "train_samples": int(x_train.shape[0]),
        "test_samples": int(x_test.shape[0]),
        "features": FEATURE_NAMES,
        "task": "classification",
        "threshold": threshold,
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
        "confusion_matrix": matrix_output,
        "report": classification_report(
            y_test,
            predictions,
            labels=list(range(len(class_names))),
            target_names=class_names,
            zero_division=0,
        ),
    }

    return model, threshold, "RandomForestClassifier", summary, class_names, benign_indexes


def train_anomaly_model(matrix: np.ndarray, contamination: float):
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
        "score_mean": float(np.mean(anomaly_scores)),
        "score_stddev": float(np.std(anomaly_scores)),
    }

    return pipeline, threshold, "IsolationForest", summary


def train_svm_anomaly_model(matrix: np.ndarray, gamma: str = "scale"):
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)
    model = OneClassSVM(kernel="rbf", nu=0.08, gamma=gamma)
    model.fit(scaled)

    pipeline = Pipeline(
        steps=[
            ("scaler", scaler),
            ("model", model),
        ]
    )

    decision_values = -pipeline.decision_function(matrix)
    probabilities = 1.0 / (1.0 + np.exp(-decision_values))
    threshold = float(np.quantile(probabilities, 0.92))

    summary = {
        "samples": int(matrix.shape[0]),
        "features": FEATURE_NAMES,
        "task": "anomaly",
        "score_mean": float(np.mean(probabilities)),
        "score_stddev": float(np.std(probabilities)),
    }

    return pipeline, threshold, "OneClassSVM", summary


def main():
    parser = argparse.ArgumentParser(description="Train the ThreatLens attack model.")
    parser.add_argument("--input", help="Optional path to JSON/JSONL/CSV training data.")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path to write the trained model bundle.",
    )
    parser.add_argument(
        "--rf-output",
        default=str(DEFAULT_RF_OUTPUT),
        help="Path to write the Random Forest model bundle.",
    )
    parser.add_argument(
        "--svm-output",
        default=str(DEFAULT_SVM_OUTPUT),
        help="Path to write the SVM model bundle.",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=2200,
        help="Number of synthetic labeled samples to generate when no input is provided.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.08,
        help="Expected anomaly fraction for IsolationForest fallback training.",
    )

    args = parser.parse_args()

    input_path = args.input
    if not input_path and DEFAULT_INPUT.exists():
        input_path = str(DEFAULT_INPUT)

    if input_path:
        records, labels = load_training_records(input_path)
    else:
        records, numeric_labels = build_synthetic_labeled_records(max(args.samples, 600))
        labels = ["benign" if int(label) == 0 else "malicious" for label in numeric_labels]

    if not records:
        raise ValueError("No training records available")

    minimum_samples = max(args.samples, 600)
    records, labels = augment_training_records(records, labels, minimum_samples)

    matrix = build_training_matrix(records)

    trained_at = datetime.now(timezone.utc).isoformat()

    normalized_labels = [str(label) for label in labels] if labels else []
    use_supervised = bool(normalized_labels) and len(set(normalized_labels)) > 1

    if use_supervised:
        rf_model, rf_threshold, rf_algorithm, rf_summary, class_names, benign_indexes = train_supervised_model(
            matrix, normalized_labels
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
        rf_output_path = Path(args.rf_output)
        rf_output_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(rf_artifact, rf_output_path)
    else:
        rf_artifact = None
        rf_output_path = Path(args.rf_output)

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
    svm_output_path = Path(args.svm_output)
    svm_output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(svm_artifact, svm_output_path)

    legacy_model, legacy_threshold, legacy_algorithm, legacy_summary = train_anomaly_model(
        matrix, args.contamination
    )
    legacy_artifact = {
        "model": legacy_model,
        "feature_names": FEATURE_NAMES,
        "threshold": legacy_threshold,
        "algorithm": legacy_algorithm,
        "task": "anomaly",
        "trained_at": trained_at,
        "training_summary": legacy_summary,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(legacy_artifact, output_path)

    print(f"Legacy model saved to {output_path}")
    print(f"SVM model saved to {svm_output_path}")
    if rf_artifact:
        print(f"Random Forest model saved to {rf_output_path}")
    else:
        print("Random Forest model skipped because labeled classes were not available")
    print(f"Samples: {legacy_summary['samples']}")
    print(f"Legacy threshold: {legacy_threshold:.4f}")
    print(f"SVM threshold: {svm_threshold:.4f}")
    if rf_artifact:
        print(f"RF accuracy: {rf_summary['accuracy']:.4f}")
        print(f"RF weighted F1: {rf_summary['f1_score']:.4f}")


if __name__ == "__main__":
    main()
