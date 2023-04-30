from aes import s_box as s, inv_s_box as si, AES
from pwn import *

def solve(c):
    candidates = []
    k = [0] * 16
    k1 = [0] * 16
    for x in range(256):
        # K1_13, GUESS
        k1[12] = x
        # K0_13, PED 13
        # c[12] = k1[12] ^ s[k[12]]
        k[12] = si[c[12] ^ k1[12]]
        # K1_9, KS 13
        # k1[12] = k[12] ^ k1[8]
        k1[8] = k1[12] ^ k[12]
        # K0_9, PED 9
        # c[8] = k1[8] ^ s[k[8]]
        k[8] = si[c[8] ^ k1[8]]
        # K1_5, KS 9
        # k1[8] = k[8] ^ k1[4]
        k1[4] = k1[8] ^ k[8]
        # K0_5, PED 5
        # c[4] = k1[4] ^ s[k[4]]
        k[4] = si[c[4] ^ k1[4]]
        # K1_1, KS 5
        # k1[4] = k[4] ^ k1[0]
        k1[0] = k1[4] ^ k[4]
        # K0_1, PED 1
        # c[0] = k1[0] ^ s[k[0]]
        k[0] = si[c[0] ^ k1[0]]
        # K0_14, KS 1
        # k1[0] = k[0] ^ s[k[13]] ^ 1
        k[13] = si[k1[0] ^ k[0] ^ 1]
        # K1_10, PED 10
        # c[9] = k1[9] ^ s[k[13]]
        k1[9] = c[9] ^ s[k[13]]
        # K1_14, KS 14
        # k1[13] = k[13] ^ k1[9]
        k1[13] = k[13] ^ k1[9]
        # K0_2, PED 14
        # c[13] = k1[13] ^ s[k[1]]
        k[1] = si[c[13] ^ k1[13]]
        for y in range(256):
            # K1_4, GUESS
            k1[3] = y
            # K0_16, PED 4
            # c[3] = k1[3] ^ s[k[15]]
            k[15] = si[c[3] ^ k1[3]]
            # K0_4, KS 4
            # k1[3] = k[3] ^ s[k[12]]
            k[3] = k1[3] ^ s[k[12]]
            # K1_8, PED 8
            # c[7] = k1[7] ^ s[k[3]]
            k1[7] = c[7] ^ s[k[3]]
            # K0_8, KS 8
            # k1[7] = k[7] ^ k1[3]
            k[7] = k1[7] ^ k1[3]
            # K1_12, PED 12
            # c[11] = k1[11] ^ s[k[7]]
            k1[11] = c[11] ^ s[k[7]]
            # K0_12, KS 12
            # k1[11] = k[11] ^ k1[7]
            k[11] = k1[11] ^ k1[7]
            # K1_16, PED 16
            # c[15] = k1[15] ^ s[k[11]]
            k1[15] = c[15] ^ s[k[11]]
            # K1_16, KS 16 (check)
            # k1[15] = k[15] ^ k1[11]
            if k1[15] == k[15] ^ k1[11]:
                for z in range(256):
                    # K1_3, GUESS
                    k1[2] = z
                    # K0_3, KS 3
                    # k1[2] = k[2] ^ s[k[15]]
                    k[2] = k1[2] ^ s[k[15]]
                    # K1_11, PED 11
                    # c[10] = k1[10] ^ s[k[2]]
                    k1[10] = c[10] ^ s[k[2]]
                    # K0_11, PED 3
                    # c[2] = k1[2] ^ s[k[10]]
                    k[10] = si[c[2] ^ k1[2]]
                    # K1_7, KS 11
                    # k1[10] = k[10] ^ k1[6]
                    k1[6] = k1[10] ^ k[10]
                    # K0_7, KS 7
                    # k1[6] = k[6] ^ k1[2]
                    k[6] = k1[6] ^ k1[2]
                    # K0_15, PED 7
                    # c[6] = k1[6] ^ s[k[14]]
                    k[14] = si[c[6] ^ k1[6]]
                    # K1_15, KS 15
                    # k1[14] = k[14] ^ k1[10]
                    k1[14] = k[14] ^ k1[10]
                    # K1_15, PED 15 (check)
                    # c[14] = k1[14] ^ s[k[6]]
                    if k1[14] == c[14] ^ s[k[6]]:
                        # K1_2, KS 2
                        # k1[1] = k[1] ^ s[k[14]]
                        k1[1] = k[1] ^ s[k[14]]
                        # K0_6, PED 2
                        # c[1] = k1[1] ^ s[k[5]]
                        k[5] = si[c[1] ^ k1[1]]
                        # K1_6, KS 6
                        # k1[5] = k[5] ^ k1[1]
                        k1[5] = k[5] ^ k1[1]
                        # K0_10, PED 6
                        # c[5] = k1[5] ^ s[k[9]]
                        k[9] = si[c[5] ^ k1[5]]
                        # K0_10, KS 10 (check)
                        # k1[9] = k[9] ^ k1[5]
                        if k[9] == k1[9] ^ k1[5]:
                            candidates.append(k[:])
    return candidates

p = remote("localhost", 7774)
zeros = b"\x00" * (16 * 2)
p.sendline(zeros.hex().encode())
p.recvuntil(b"message:\n")
oracle = bytes.fromhex(p.recvlineS())
p.recvuntil(b"flag:\n")
chall = bytes.fromhex(p.recvlineS())
for key in solve(oracle[:16]):
    cipher = AES(key)
    if bytes(cipher.encrypt(zeros)) == oracle:
        response = bytes(cipher.decrypt(chall))
        p.sendline(response.hex().encode())
        p.recvuntil(b"flag:\n")
        print(p.recvlineS())
        break
