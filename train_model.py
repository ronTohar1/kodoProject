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



def load_model():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

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
    mlp = MLPClassifier(hidden_layer_sizes=(20,20), max_iter=500, alpha=0.0001,
                        solver='sgd', verbose=10, random_state=21,tol=0.000000001)

    # Define the k-fold cross-validation
    kfold = KFold(n_splits=5)

    # Perform k-fold cross-validation and get predictions
    predictions = cross_val_predict(mlp, X, y, cv=kfold)

    # Calculate accuracy, recall, precision, and f1 score
    acc = accuracy_score(y, predictions)
    recall = recall_score(y, predictions, average='weighted')
    precision = precision_score(y, predictions, average='weighted')
    f1 = f1_score(y, predictions, average='weighted')

    # Print the results
    print("Accuracy:", acc)
    print("Recall:", recall)
    print("Precision:", precision)
    print("F1 Score:", f1)

    

    # Plot the results
    plt.plot(['accuracy', 'recall', 'precision', 'f1_score'], [acc, recall, precision, f1])
    plt.xlabel('Metric')
    plt.ylabel('Score')
    plt.title('Neural Network Performance')
    plt.show()



if __name__ == "__main__":
    train_model()