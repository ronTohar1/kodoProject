import subprocess
import re
import os
import json

from utilities import NUMBER_OF_FILES, ONLY_STATIC


def extract_strings(filename):

    command = f"floss {filename} --only static -j"
    if not ONLY_STATIC:
        command = f"floss {filename} -j"
    
    result = subprocess.run(command, shell=True,stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    # convert output from json to dictionary
    output = result.stdout.decode()
    output = json.loads(output)
    strings =  output["strings"]
    all_strings = []
    for key in strings.keys():
        all_strings += [a["string"] for a in strings[key] ]

    return all_strings

def main():
    cwd = os.getcwd()
    malwares = os.path.join(cwd,"binaries\miners")
    for file in os.listdir(malwares)[:NUMBER_OF_FILES]:
        filename = os.path.join(malwares, file)
        strings = extract_strings(filename)
        # check if strings contain ips or urls
        has_ip ,has_url, has_domain = False, False, False
        for string in strings:
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",string):
                has_ip = True
            if re.search(r"www\.\w+\.\w+",string):
                has_url = True
            domain_pattern = r'[a-zA-Z0-9]+\.[a-zA-Z]{2,}'
            if re.search(domain_pattern,string):
                has_domain = True
        return strings, has_ip, has_url, has_domain
main()
# to_out()