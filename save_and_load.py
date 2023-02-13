import pickle
import pandas as pd
from utilities import *

def save_model(model):
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

def load_model():
    with open(MODEL_PATH, 'rb') as f:
        return pickle.load(f)

def load_dataset():
    df = pd.read_csv(DATASET_PATH, index_col=0)
    return df