import hashlib
import string
from pwn import *

HOST = '0.0.0.0'
PORT = 7001


def md5sum(b: bytes):
    return hashlib.md5(b).digest()[:3]

target = md5sum(b'echo lmao')

cmd = b"cat flag.txt; echo '"
junk = b''
count = 1
found = False

for i in range(256 * 256 * 256):
    junk = str(i).encode()
    if md5sum(cmd + junk + b"'") == target:
        print(junk)
        cmd = cmd + junk + b"'"
        found = True
        break

if found:
    p = remote(HOST, PORT)
    p.sendlineafter(b'> ', cmd)
    print("FLAG: %s" % p.recvline().decode())
