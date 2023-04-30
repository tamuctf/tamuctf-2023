# inspector gadget

Author: `_mac_`

Inspector Gadget gave me this binary with one goal. pwn.

## Dev Notes
Given `inspector_gadget` binary file and `libc.so.6`
Set up remote with `make run`
Get needed files with `make extract`

## Solution
This is a classic ret2libc attack. The goal is to leak an address into libc to calculate its base address, then call `system()`. We can do this with 2 payloads. The first one uses `puts()` to leak the contents the GOT entry for `__libc_start_main` (this will have a live pointer into libc), then recurses on `pwnme()` to allow for a second go at the buffer overflow. For the second payload, we can use our leaked address to compute the base address of libc since ASLR adds a positive shift. Armed with the base address, we can call any function in libc, including `system()`. Conveniently, "/bin/sh" is in both the binary and libc. See `solve.py` for details.

Flag: `gigem{ret2libc_r0p_g04t3d}`
