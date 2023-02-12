import pefile
from utilities import MINERS_PATH, NUMBER_OF_FILES, MALWARE_PATH, BENIGN_PATH, MINER_LABEL, NON_MINER_LABEL
import os


def is_pe_file(filepath):
    try:
        pe = pefile.PE(filepath)
        return True
    except pefile.PEFormatError:
        return False


def main():
    miners_dir = os.path.join(os.getcwd(), MINERS_PATH)
    malware_dir = os.path.join(os.getcwd(), MALWARE_PATH)
    benign_dir = os.path.join(os.getcwd(), BENIGN_PATH)


main()