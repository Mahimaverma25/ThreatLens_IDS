import pickle

def load_attack_model():

    with open("models/attack_model.pkl", "rb") as f:
        model = pickle.load(f)

    return model