import capstone
import os

def crypto_functions(file):
    # Define the known opcode sequences for specific cryptographic functions
    sha256_opcodes = [b'\x53\x48\x83\xec\x20', b'\x48\x89\xd9', b'\x48\x89\xc2', b'\x48\x8b\x11', b'\xff\xd2', b'\x48\x89\xc1', b'\xc3']
    scrypt_opcodes = [b'\x55\x48\x89\xe5', b'\x48\x83\xec\x28', b'\xc7\x45\xf4\x05\x00\x00\x00', b'\x48\x8b\x45\x08', b'\xff\xd0', b'\x5d\xc3']
    ethash_opcodes = [b'\x55\x48\x89\xe5', b'\x48\x83\xec\x20', b'\xc7\x45\xf4\x07\x00\x00\x00', b'\x48\x8b\x45\x08', b'\xff\xd0', b'\x5d\xc3']
    groestl_opcodes = [b'\x55\x48\x89\xe5', b'\x48\x83\xec\x20', b'\xc7\x45\xf4\x05\x00\x00\x00', b'\x48\x8b\x45\x08', b'\xff\xd0', b'\x5d\xc3']
    blake2s_opcodes = [b'\x55\x48\x89\xe5', b'\x48\x83\xec\x20', b'\xc7\x45\xf4\x04\x00\x00\x00', b'\x48\x8b\x45\x08', b'\xff\xd0', b'\x5d\xc3']
    keccak_opcodes = [b'\x55\x48\x89\xe5', b'\x48\x83\xec\x20', b'\xc7\x45\xf4\x06\x00\x00\x00', b'\x48\x8b\x45\x08', b'\xff\xd0', b'\x5d\xc3']
    lyra2z_opcodes = [b'\x55\x48\x89\xe5', b'\x48\x83\xec\x20', b'\xc7\x45\xf4\x06\x00\x00\x00', b'\x48\x8b\x45\x08', b'\xff\xd0', b'\x5d\xc3']

    # Load the binary file into memory
    with open(file, 'rb') as f:
        binary = f.read()
        # print("read")

    # Disassemble the binary file
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(binary, 0x0):
        # Check if the current opcode sequence matches a known cryptographic function
        if i.bytes in sha256_opcodes:
            print('SHA-256 function detected at address: 0x{:x}'.format(i.address))
        elif i.bytes in scrypt_opcodes:
            print('Scrypt function detected at address: 0x{:x}'.format(i.address))
        elif i.bytes in ethash_opcodes:
            print('Ethash function detected at address: 0x{:x}'.format(i.address))
        elif i.bytes in groestl_opcodes:
            print('Groestl function detected at address: 0x{:x}'.format(i.address))
        elif i.bytes in blake2s_opcodes:
            print('Blake2s function detected at address: 0x{:x}'.format(i.address))
        elif i.bytes in keccak_opcodes:
            print('Keccak function detected at address: 0x{:x}'.format(i.address))
        elif i.bytes in lyra2z_opcodes:
            print('Lyra2z function detected at address: 0x{:x}'.format(i.address))
        
    # else:
    #     print("Nothing detected")

def main():
    cwd = os.getcwd()
    malwares = os.path.join(cwd,"binaries/miners")
    for file in os.listdir(malwares):
        file_path = os.path.join(malwares, file)
        crypto_functions(file_path)

main()