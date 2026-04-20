import joblib


def load_model(path="models/attack_model.pkl"):
    return joblib.load(path)
