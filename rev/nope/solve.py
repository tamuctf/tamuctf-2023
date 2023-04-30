from pwn import *
import struct
from string import printable

exe = ELF('./patched_nope')
context.binary = exe
context.log_level = 'CRITICAL'

print(''.join([hex(x)[2:] for x in struct.pack('<i', 0x1070 - (0x1383+5))]))
print(''.join([hex(x)[2:] for x in struct.pack('<i', 0x1070 - (0x138c+5))]))
print(''.join([hex(x)[2:] for x in struct.pack('<i', 0x1090 - (0x1391+5))]))

print(disasm(asm(
    """
    lea rdi, [rbp-0x20]
    """
    )))



charset = '{}_' + printable
flag = ''
flaglen = 0

while flaglen < 23:
    for c in charset:
        p = process([exe.path, flag + c + 'a'*(22-flaglen)])
        x = p.recv(24)
        y = p.recvline(24)
        p.close()
        if len(x) <= flaglen or len(y) <= flaglen:
            continue
        if x[flaglen] == y[flaglen]:
            flag += c
            flaglen += 1
            break
    print(flaglen)
    print(flag)

p = process(['./nope', flag])
print(p.recvline())

exit()

while len(flag) != 23:
    p = process([exe.path, flag + b'A'*(23-len(flag))])
    out = p.readline().strip()
    out += b'\x00'*(4-len(out))
    x = struct.unpack('<i', out)[0]
    p.close()
    flag += (0xff + x).to_bytes(1, byteorder='big')
    print(flag)

print(p.readline())

