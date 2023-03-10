import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from save_and_load import load_dataset, load_model, save_model
from utilities import *
from matplotlib import pyplot as plt

def train_models():
    # Load the data
    data = load_dataset()
    # shuffle data and remove 50 percent of the data
    data = data.sample(frac=1).reset_index(drop=True)
    data = data.iloc[:int(len(data)), :]


    X = data.iloc[:, :-1].values
    y = data.iloc[:, -1].values

    # Split the data into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=0)

    # Define the models and their hyperparameters
    mlp = MLPClassifier()
    param_grid_mlp = {
        'hidden_layer_sizes': [(10, 10), (20, 20), (30, 30)],
        'alpha': [0.0001, 0.001, 0.01, 0.1],
        'max_iter': [100, 135, 150]
    }

    forest = RandomForestClassifier()
    param_grid_forest = {
        'n_estimators': [10, 100, 250],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 4, 6, 8]
    }

    xgb = XGBClassifier()
    param_grid_xgb = {
        'max_depth': [3, 5, 7, 9],
        'learning_rate': [0.001, 0.01, 0.1, 1],
        'n_estimators': [50, 100, 150]
    }

    # Define a list of models and their parameter grids
    models = [
        (mlp, param_grid_mlp),
        (forest, param_grid_forest),
        (xgb, param_grid_xgb)
    ]

    # Train the models and choose the best one
    best_model = None
    best_accuracy = 0
    best_recall = 0
    best_precision = 0
    best_f1 = 0

    for model, param_grid in models:
        grid_search = GridSearchCV(model, param_grid, cv=5, scoring='accuracy')
        grid_search.fit(X_train, y_train)
        y_pred = grid_search.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)

        print("Model: ", type(model).__name__)
        print("Best parameters: ", grid_search.best_params_)
        print("Accuracy: ", accuracy)
        print("Recall: ", recall)
        print("Precision: ", precision)
        print("F1 score: ", f1)
        print()

        if accuracy > best_accuracy:
            best_model = grid_search.best_estimator_
            best_accuracy = accuracy
            best_recall = recall
            best_precision = precision
            best_f1 = f1

    print("Best model: ", type(best_model).__name__)
    print("Best accuracy: ", best_accuracy)
    print("Best recall: ", best_recall)
    print("Best precision: ", best_precision)
    print("Best F1 score: ", best_f1)

  
    x = [1, 2, 3, 4]
    y = [best_accuracy, best_recall, best_precision, best_f1]

    fig, ax = plt.subplots()
    ax.scatter(x, y)

    ax.set_xlim([0, 5])
    ax.set_ylim([0.8, 1])

    ax.set_xticks([1, 2, 3, 4])
    ax.set_xticklabels(['Accuracy', 'Recall', 'Precision', 'F1'])
    ax.set_yticks([ 0.9, 0.95,1])

    ax.set_xlabel('Metric')
    ax.set_ylabel('Value')

    plt.show()

    # Save the best model
    save_model(best_model)


def main():
    train_models()

if __name__ == "__main__":
    main()