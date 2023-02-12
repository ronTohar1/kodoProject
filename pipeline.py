import pandas as pd
import numpy as np
import os

import floss
import find_imports
import pickle

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
    imports_to_freq = find_imports.main()
    used_strings = imports_to_freq.keys()
    # strings, has_ip, has_url, has_domain = floss.main()

    # print(used_strings)
    features = list(set(used_strings) | set(network_functions)) + ["has_ip","has_url","has_domain"] + ["entropy"]
    # save features with pickle but first delete the old one
    if os.path.exists("features.pkl"):
        os.remove("features.pkl")
    with open("features.pkl", "wb") as f:
        pickle.dump(features, f)

def reload_features():
    with open("features.pkl", "rb") as f:
        features = pickle.load(f)
    return features

def main():
    create_features()
    # features = reload_features()
    # print(features)


if __name__ == "__main__":
    main()