# pwnme

Author: `_mac_`

pwn me. that's it.

## Dev Notes
Given `pwnme` binary file and `libpwnme.so`
Set up remote with `make run`
Get needed files with `make extract`

## Solution
Using the following gadgets in `pwnme` we can call anything in a shared library if there's a got entry for one of it's functions and we know the offset to what we want to call:

```
0x0000000000401191 : mov rax, qword ptr [rdi] ; ret
0x00000000004011b2 : sub rax, rsi ; ret
0x000000000040109c : jmp rax
```

Unfortunately, our read is too small for this to work, the payload is 88 bytes long but we only have 72 bytes of read! No problem, since what we can do is write the last part of the payload, then ret to almost the start of main, where it does `sub rsp, 0x18` to shift the stack back down, write the first part of our payload, and this gives us enough bytes to win! See `solve.py` for details

Flag: `gigem{r0p_g4dg3ts_r_c00l}`
