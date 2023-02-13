import os
from utilities import *
import pandas as pd


malwares_path = os.path.join(DIKE_DS_PATH, DIKE_MALWARE)
benigns_path = os.path.join(DIKE_DS_PATH, DIKE_BENIGN)

malware_csv = os.path.join(DIKE_DS_PATH,DIKE_MAL_LABELS)
benign_csv = os.path.join(DIKE_DS_PATH, DIKE_BENIGN_LABELS)

NUMBER_OF_GENERIC_MALWARES = 200
NUMBER_OF_BENIGNS = 200

def get_generic_malware():
    df = pd.read_csv(malware_csv)
    malware_hashes = [x.split(".")[0] for x in os.listdir(malwares_path) if x.endswith(".exe")]
    # get all rows with 'hash' in malware_hashes and malice >= 0.85 and generic >=0.5
    df = df[df['hash'].isin(malware_hashes)]
    df = df[(df['malice'] >= 0.85) & (df['generic'] >= 0.5)]
    hashes = df['hash'].tolist()
    for hash in hashes[:NUMBER_OF_GENERIC_MALWARES]:
        os.rename(os.path.join(malwares_path, f"{hash}.exe"), os.path.join(MALWARE_PATH, f"{hash}.exe"))

def get_benigns():
    df = pd.read_csv(benign_csv)
    benign_hashes = [x.split(".")[0] for x in os.listdir(benigns_path) if x.endswith(".exe")]
    df = df[df['hash'].isin(benign_hashes)]
    hashes = df['hash'].tolist()
    for hash in hashes[:NUMBER_OF_BENIGNS]:
        os.rename(os.path.join(benigns_path, f"{hash}.exe"), os.path.join(BENIGN_PATH, f"{hash}.exe"))

def main():
    get_generic_malware()
    get_benigns()

if __name__ == "__main__":
    main()