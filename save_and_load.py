import pickle
from utilities import *

def save_model(model):
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

def load_model():
    with open(MODEL_PATH, 'rb') as f:
        return pickle.load(f)

def load_dataset():
    with open(NAME_OF_CSV, 'rb') as f:
        return pickle.load(f)