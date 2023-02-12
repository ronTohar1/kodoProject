import pefile
import os 
from utilities import NUMBER_OF_FILES

def add_to_dict(dict, import_name):
    if import_name not in dict:
        dict[import_name] = 1
    else:
        dict[import_name] += 1

def print_dict(dict1):
    print({k: v for k, v in sorted(dict1.items(), key=lambda item: item[1])})

def extract_functions(dict1,filename):
    try:
        pe = pefile.PE(filename)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imported_function in entry.imports:
                if imported_function.name:
                    add_to_dict(dict1,imported_function.name.decode())
                else:
                    add_to_dict(dict1,"<unknown>")
    except:
        # print("CURROPTED")
        pass


def main():
    cwd = os.getcwd()
    dict1 = {}
    malwares = os.path.join(cwd,"binaries/miners")
    for file in os.listdir(malwares)[:NUMBER_OF_FILES]:
        filename = os.path.join(malwares, file)
        functions = extract_functions(dict1,filename)
    return dict1     

main()