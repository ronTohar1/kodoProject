NUMBER_OF_FILES = 310
NUMBER_OF_MALWARE = 150
NUMBER_OF_BENIGN = NUMBER_OF_MALWARE

ONLY_STATIC = True

DATASET_PATH = "miners.csv"
MODEL_PATH="./models/" + "miners_model.pkl"

DIKE_DS_PATH = "../DikeDataset-main"
DIKE_MALWARE = "files/malware"
DIKE_BENIGN = "files/benign"
DIKE_MAL_LABELS = "labels/malware.csv"
DIKE_BENIGN_LABELS = "labels/benign.csv"

MINERS_PATH = "../binaries/miners"
MALWARE_PATH = "../binaries/malware"
BENIGN_PATH = "../binaries/benign"

MINER_LABEL = 1
NON_MINER_LABEL = 0



