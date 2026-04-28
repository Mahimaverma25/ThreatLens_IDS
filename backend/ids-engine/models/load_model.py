import os
import joblib
import numpy as np

from utils.logger import get_logger
from utils.feature_extractor import extract_features, features_to_vector

logger = get_logger("ids-engine.model-loader")


class ModelLoader:
    def __init__(self):
        self.rf_model = None
        self.svm_model = None
        self.if_model = None

        self.rf_threshold = 0.55
        self.svm_threshold = 0.5
        self.if_threshold = 0.5

        self.feature_names = None

    # ---------- LOAD MODELS ----------

    def load_models(
        self,
        rf_path="models/rf_model.pkl",
        svm_path="models/svm_model.pkl",
        if_path="models/attack_model.pkl",
    ):
        """
        Load all ML models
        """

        # Random Forest (classification)
        if os.path.exists(rf_path):
            artifact = joblib.load(rf_path)
            self.rf_model = artifact.get("model")
            self.rf_threshold = artifact.get("threshold", 0.55)
            self.feature_names = artifact.get("feature_names")
            logger.info("Random Forest model loaded")

        # One-Class SVM (anomaly)
        if os.path.exists(svm_path):
            artifact = joblib.load(svm_path)
            self.svm_model = artifact.get("model")
            self.svm_threshold = artifact.get("threshold", 0.5)
            logger.info("SVM model loaded")

        # Isolation Forest (fallback)
        if os.path.exists(if_path):
            artifact = joblib.load(if_path)
            self.if_model = artifact.get("model")
            self.if_threshold = artifact.get("threshold", 0.5)
            logger.info("Isolation Forest model loaded")

        if not any([self.rf_model, self.svm_model, self.if_model]):
            raise RuntimeError("No ML models could be loaded!")

    # ---------- FEATURE PREP ----------

    def _prepare_input(self, event):
        features = extract_features(event)
        vector = features_to_vector(features)
        return np.array([vector])  # shape (1, n_features)

    # ---------- PREDICTION ----------

    def predict(self, event):
        """
        Hybrid ML prediction
        """

        try:
            X = self._prepare_input(event)

            results = {}

            # ----- Random Forest -----
            if self.rf_model:
                probs = self.rf_model.predict_proba(X)[0]
                max_prob = float(np.max(probs))
                pred_class = int(np.argmax(probs))

                results["rf"] = {
                    "is_attack": pred_class != 0,
                    "confidence": max_prob,
                    "type": "classification",
                }

            # ----- SVM -----
            if self.svm_model:
                score = -float(self.svm_model.decision_function(X)[0])
                prob = 1 / (1 + np.exp(-score))

                results["svm"] = {
                    "is_attack": prob > self.svm_threshold,
                    "confidence": prob,
                    "type": "anomaly",
                }

            # ----- Isolation Forest -----
            if self.if_model:
                score = -float(self.if_model.decision_function(X)[0])

                results["if"] = {
                    "is_attack": score > self.if_threshold,
                    "confidence": score,
                    "type": "anomaly",
                }

            # ---------- FINAL DECISION ----------

            return self._combine_results(results)

        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {
                "is_attack": False,
                "confidence": 0.0,
                "reason": "ML prediction error",
            }

    # ---------- HYBRID DECISION ----------

    def _combine_results(self, results):
        """
        Combine RF + SVM + IF results
        """

        attacks = []
        confidences = []

        for model_name, res in results.items():
            if res["is_attack"]:
                attacks.append(model_name)
                confidences.append(res["confidence"])

        if attacks:
            return {
                "is_attack": True,
                "confidence": max(confidences),
                "models_triggered": attacks,
                "detection_type": "ml_hybrid",
                "reason": f"Detected by {', '.join(attacks)}",
            }

        return {
            "is_attack": False,
            "confidence": 0.0,
            "detection_type": "ml",
            "reason": "No anomaly detected",
        }


# ---------- GLOBAL INSTANCE ----------

model_loader = ModelLoader()


def load_all_models():
    model_loader.load_models()


def predict_event(event):
    return model_loader.predict(event)