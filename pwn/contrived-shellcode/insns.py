from capstone import *
from collections import defaultdict

allowed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15]
insns = defaultdict(set)
md = Cs(CS_ARCH_X86, CS_MODE_64)
code = bytearray([0, 0, 0, 0, 0])
for a in allowed:
    code[0] = a
    for b in allowed:
        code[1] = b
        for c in allowed:
            code[2] = c
            for d in allowed:
                code[3] = d
                for e in allowed:
                    code[4] = e
                    for _, _, mnemonic, op_str in md.disasm_lite(code, 0):
                        if "eax, 0x" not in op_str:
                            insns[mnemonic].add(op_str)
                        break

blacklist = ["pi2fd", "prefetchw", "sgdt", "str", "femms", "invd", "ud2", "sidt", "pi2fw", "sldt", "lar", "lsl", "clts", "sysret", "wbinvd", "or"]
for b in blacklist:
    del insns[b]

for mn, ops in insns.items():
    for op in ops:
        print(mn, op)
