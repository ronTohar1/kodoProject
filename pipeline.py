import pandas as pd
import numpy as np
import os

import floss
import find_imports
import entropy as ent
import pickle

from utilities import NUMBER_OF_FILES, ONLY_STATIC, MINERS_PATH, MALWARE_PATH, BENIGN_PATH, MINER_LABEL, NON_MINER_LABEL

network_functions = [
    "connect",
    "send",
    "recv",
    "getaddrinfo",
    "WSASocketA",
    "WSASocketW",
    "gethostbyname",
    "gethostbyaddr",
    "inet_addr",
    "inet_ntoa",
    "getpeername",
    "getsockname"
]

def create_features():
    featuers = []
    imports_to_freq = find_imports.get_all_files_imports()
    used_strings = imports_to_freq.keys() # strings of the imports being used

    features = list(set(used_strings) | set(network_functions)) + ["has_ip","has_url","has_domain"] + ["entropy"] + ["label"]


    # save features with pickle but first delete the old one
    if os.path.exists("features.pkl"):
        os.remove("features.pkl")
    with open("features.pkl", "wb") as f:
        pickle.dump(features, f)

def reload_features():
    with open("features.pkl", "rb") as f:
        features = pickle.load(f)
    return features

def add_directory(df, directory, label):
    features = df.columns
    for file in os.listdir(directory)[:NUMBER_OF_FILES]:
        file = os.path.join(directory, file)
        # get the imports of each malware
        imports = find_imports.get_file_imports(file)
        # get the entropy of each malware
        entropy = ent.binary_file_entropy(file)
        # get the floss info of each malware
        strings, has_ip, has_url, has_domain = floss.get_floss_info(file)

        # create a new row in the df, with the features and the label
        new_row = {}
        for feature in features:
            if feature in imports or feature in strings:
                new_row[feature] = 1
            elif feature in network_functions:
                new_row[feature] = 1
            elif feature == "has_ip":
                new_row[feature] = int(has_ip)
            elif feature == "has_url":
                new_row[feature] = int(has_url)
            elif feature == "has_domain":
                new_row[feature] = int(has_domain)
            elif feature == "entropy":
                new_row[feature] = entropy
            elif feature == "label":
                new_row[feature] = label
            else:
                new_row[feature] = 0
        df = df.append(new_row, ignore_index=True)
    return df

# Create a df file with the features and the labels for each Malware
def create_df():
    # create a pandas df with the features
    features = reload_features()
    df = pd.DataFrame(columns=features)
    miners_dir = os.path.join(os.getcwd(), MINERS_PATH)
    df = add_directory(df,miners_dir, MINER_LABEL)
    print(df)




def main():
    # create_features()
    df = create_df()
    print(df)

if __name__ == "__main__":
    main()