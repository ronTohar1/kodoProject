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
from sklearn.model_selection import train_test_split
from train_model import load_model, load_dataset

def evaluate_by_epochs():

    mlp = load_model()
    mlp.verbose=2
    mlp.max_iter=20
    df = load_dataset()
    X = df.drop("label", axis=1)
    y = df["label"]

    # Initialize lists to store the metrics
    accuracies = []
    precisions = []
    recalls = []
    f1_scores = []

    num_epoches = 20

    # Train the model
    for epoch in range(1, num_epoches+1):
        mlp.fit(X, y)
        y_pred = mlp.predict(X)
        
        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred)
        recall = recall_score(y, y_pred)
        f1 = f1_score(y, y_pred)
        
        accuracies.append(accuracy)
        precisions.append(precision)
        recalls.append(recall)
        f1_scores.append(f1)
        
        if epoch % 10 == 0:
            print("Epoch:", epoch)
            print("Accuracy:", accuracy)
            print("Precision:", precision)
            print("Recall:", recall)
            print("F1 Score:", f1)
            print()

    # Plot the metrics as a function of the number of epochs
    plt.plot(range(1, num_epoches+1), accuracies, label="Accuracy")
    plt.plot(range(1, num_epoches+1), precisions, label="Precision")
    plt.plot(range(1, num_epoches+1), recalls, label="Recall")
    plt.plot(range(1, num_epoches+1), f1_scores, label="F1 Score")
    plt.xlabel("Epoch")
    plt.ylabel("Metric Value")
    plt.legend()
    plt.show()

def evaluate_model():
    # mlp = load_model()
    mlp = MLPClassifier(hidden_layer_sizes=(30,30), activation='relu', solver='adam', max_iter=100 , alpha=0.1)
    mlp.verbose = 10
    data = load_dataset()
    data = data.sample(frac=1).reset_index(drop=True)
    data = data.iloc[:int(len(data)/3), :]


    X = data.iloc[:, :-1].values
    y = data.iloc[:, -1].values

    # Split the data into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    # Split the data into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)
    kfold = KFold(n_splits=5)

    # mlp.fit(X, y)
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

def main():
    evaluate_model()

if __name__ == "__main__":
    main()