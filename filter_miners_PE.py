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
    miners_dir = MINERS_PATH
    miners = [x for x in os.listdir(miners_dir)]
    miners = [x for x in miners if is_pe_file(os.path.join(miners_dir, x))][:NUMBER_OF_FILES]
    # delete what is not in miners but is in miners_dir
    for miner_file in os.listdir(miners_dir):
        if miner_file not in miners:
            os.remove(os.path.join(miners_dir, miner_file))
