from pwn import *
from pathlib import Path
from subprocess import run

run("cargo build --release", shell=True)
elf = Path("target/x86_64-unknown-linux-musl/release/solution").read_bytes()

p = remote("localhost", 16983)
p.sendline(b"execute")
p.sendline(str(len(elf)).encode())
p.send(elf)
p.recvline()
flag = p.recvuntil(b"}")
print("".join(chr(x) for x in flag if 32 <= x <= 127))
