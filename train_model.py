import pickle
import os
import pandas as pd
from tqdm import tqdm
from utilities import *
import numpy as np
import matplotlib.pyplot as plt
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import cross_val_predict, cross_val_score, KFold
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import make_scorer

def load_model():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    return model


def save_model(model):
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

def load_dataset():
    df = pd.read_csv(NAME_OF_CSV)
    return df

def train_model():
        # Split the data into features (X) and target variable (y)
    df = load_dataset()
    X = df.drop("label", axis=1)
    y = df["label"]



    # Define the model
    mlp = MLPClassifier(max_iter=200, solver='sgd', verbose=10, random_state=21, tol=0.000000001)

    # Define the hyperparameters to search
    param_grid = {'hidden_layer_sizes': [(20, 20), (30, 30), (40, 40), (10,10), (5,5)],
                'alpha': [0.0001, 0.001, 0.01]}

    # Define the k-fold cross-validation
    kfold = KFold(n_splits=5)

    # Define a scoring function based on accuracy
    scorer = make_scorer(accuracy_score)

    # Use GridSearchCV to search for the best hyperparameters
    grid_search = GridSearchCV(mlp, param_grid, scoring=scorer, cv=kfold)
    grid_search.fit(X, y)

    # Get the best parameters
    best_parameters = grid_search.best_params_

    # Train the model with the best parameters
    best_mlp = MLPClassifier(max_iter=200, solver='sgd', verbose=10, random_state=21, tol=0.000000001, 
                            hidden_layer_sizes=best_parameters['hidden_layer_sizes'],
                            alpha=best_parameters['alpha'])

    save_model(best_mlp)





if __name__ == "__main__":
    train_model()