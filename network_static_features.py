import pefile
import csv

# List of suspicious networking functions
suspicious_functions = [
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

def extract_network_functions(file_path):
    # Initialize a dictionary to store the presence of each function
    functions = {func: 0 for func in suspicious_functions}

    # Load the PE file
    pe = pefile.PE(file_path)

    # Iterate over the imported functions
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            # Check if the function is in the list of suspicious functions
            if imp.name is not None and imp.name in functions:
                functions[imp.name] = 1

    return functions



# Output a csv file for each function
for func in suspicious_functions:
    with open("{}.csv".format(func), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["File", func])
        for file_path in files:
            functions = extract_network_functions(file_path)
            writer.writerow([file_path, functions[func]])



# def main():
#     cwd = os.getcwd()
#     malwares = os.path.join(cwd,"binaries/miners")
#     for file in os.listdir(malwares):
#         file_path = os.path.join(malwares, file)
#         crypto_functions(file_path)

# main()