import math
import os 

from utilities import NUMBER_OF_FILES, ONLY_STATIC, MINERS_PATH

def binary_file_entropy(filename):
    with open(filename, "rb") as f:
        binary_data = f.read()

    frequency = [0] * 256
    for byte in binary_data:
        frequency[byte] += 1

    probability = [f / len(binary_data) for f in frequency]

    entropy = 0
    for p in probability:
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy




def main():
    cwd = os.getcwd()
    malwares = os.path.join(cwd, MINERS_PATH)
    for file in os.listdir(malwares)[:5]:
        filename = os.path.join(malwares, file)
        entropy = binary_file_entropy(filename)
    return entropy

main()