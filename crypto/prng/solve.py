from pwn import *
from math import gcd

p = remote("localhost", 7001)
p.recvline()
y = [int(p.recvlineS()) for _ in range(10)]

m = 0
for i in range(len(y) - 3):
    d0 = y[i + 1] - y[i]
    d1 = y[i + 2] - y[i + 1]
    d2 = y[i + 3] - y[i + 2]
    g = d2 * d0 - d1 * d1
    m = g if m == 0 else gcd(g, m)

t1 = (y[2] - y[1]) % m
t2 = (y[1] - y[0]) % m
a = t1 * pow(t2, -1, m) % m
c = (y[1] - a * y[0]) % m

state = y[-1]
for _ in range(10):
    state = (a * state + c) % m
    p.sendline(str(state).encode())
print(p.recvline_containsS(b"gigem"))
