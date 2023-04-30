# This code is bad don't look at this
# Encrypts a section and writes the key and size of encrypted section to a variable in the binary. 
# Usage: python3 enc.py <bin>
import secrets
import struct
import subprocess
import sys

def main():
    elf_path = sys.argv[1]
    x = subprocess.check_output(f'nm -S {elf_path}'.split(' ')).decode().split('\n')
    mprot_size_addr = 0
    foo_size_addr = 0
    key_addr = 0
    foo_addr = 0
    foo_size = 0

    for row in x:
        if 'T foo' in row:
            parts = row.split(' ')
            foo_addr = int(parts[0], 16)
            foo_size = int(parts[1], 16)
        if 'enc_key' in row:
            key_addr = int(row.split(' ')[0], 16) - 0x1000
        if 'mprot_size' in row:
            mprot_size_addr = int(row.split(' ')[0], 16) - 0x1000
        if 'foo_size' in row:
            foo_size_addr = int(row.split(' ')[0], 16) - 0x1000

    mprot_size = foo_size + (foo_addr - (foo_addr & 0xfffffffffffff000))

    print(hex(mprot_size_addr), hex(foo_size_addr))
    print(hex(foo_addr), hex(foo_size))
    print(hex(key_addr))

    key_len = 16
    key = secrets.token_bytes(key_len)
    elf = open(elf_path, 'rb+')
    elf.seek(mprot_size_addr)
    elf.write(struct.pack('<Q', mprot_size))
    elf.seek(foo_size_addr)
    elf.write(struct.pack('<Q', foo_size))
    elf.seek(key_addr)
    elf.write(key)
    elf.seek(foo_addr)
    foo_bytes = bytearray(elf.read(foo_size))

    for i in range(foo_size):
        foo_bytes[i] = foo_bytes[i] ^ key[i % key_len]

    elf.seek(foo_addr)
    elf.write(foo_bytes)


main()
