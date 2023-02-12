import pandas as pd
import numpy as np
import os

import floss
import find_imports
import pickle

from utilities import NUMBER_OF_FILES, ONLY_STATIC, MINERS_PATH

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

# Create a df file with the features and the labels for each Malware
def create_df():
    # create a pandas df with the features
    features = reload_features()
    df = pd.DataFrame(columns=features)
    miners_dir = os.path.join(os.getcwd(), MINERS_PATH)
    for file in os.listdir(miners_dir)[:NUMBER_OF_FILES]:
        
        # get the imports of each malware
        imports_to_freq = find_imports.get_all_files_imports()
        # get the entropy of each malware
        entropy = floss.get_entropy()
        # get the floss info of each malware
        strings, has_ip, has_url, has_domain = floss.get_floss_info()



def main():
    create_features()
    # features = reload_features()
    # print(features)


if __name__ == "__main__":
    main()