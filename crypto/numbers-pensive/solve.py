from pwn import *
from math import gcd

def main():
    r = remote('localhost', 7770)
    n = int(r.recvline().split()[-1])
    e = int(r.recvline().split()[-1])
    
    r.sendline(b'11')
    d_1 = int(r.recvline().split()[-1])
    r.sendline(b'1')
    r.recvuntil(b'ive:\n')

    r.sendline(b'17')
    d_2 = int(r.recvline().split()[-1])

    phi = gcd((11*d_1) - 1, (17*d_2) - 1)
    assert phi != 1

    d = pow(e, -1, phi)
    r.recvline()
    c = int(r.recvline())
    r.sendline(str(pow(c,d,n)))
    r.interactive()


if __name__ == "__main__":
    main()
