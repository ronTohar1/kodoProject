import os
from utilities import MALWARE_PATH, BENIGN_PATH, MINERS_PATH, MINER_LABEL, NON_MINER_LABEL, NUMBER_OF_FILES
import pandas as pd


ds_path = "../DikeDataset-main"
malwares_path = os.path.join(ds_path, "files/malware")
benigns_path = os.path.join(ds_path, "files/benign")

malware_csv = os.path.join(ds_path, "labels/malware.csv")
benign_csv = os.path.join(ds_path, "labels/benign.csv")

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

# get_generic_malware()
# get_benigns()