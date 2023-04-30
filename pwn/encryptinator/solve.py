from pwn import *
from Crypto.Util.number import long_to_bytes

exe = ELF('encryptinator')
context.binary = exe

#r = process()
#gdb.attach(r, gdbscript='b *encrypt')

r = remote('localhost', 9001)

r.sendline(b'1')
r.sendline(b'AAAA')
r.sendline(b'2')
r.sendline(b'-1000000')

r.recvuntil(b'flag:\n')
keyspace = long_to_bytes(int(r.recvline().strip(), 16))

r.sendline(b'2')
r.sendline(b'0')
r.recvuntil(b'flag:\n')
flag_ct = long_to_bytes(int(r.recvline().strip(), 16))

#iv = long_to_bytes(0x6893ab48f939318e)
iv = long_to_bytes(0x6893ab48f939318e)[::-1]

print(len(keyspace))
print(len(flag_ct))
print(len(iv))

for i in range(len(keyspace)-35):
    temp = xor(xor(keyspace[i:i+35], flag_ct), iv)
    if b'gigem' in temp:
        print(temp)

