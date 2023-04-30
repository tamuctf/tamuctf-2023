# Pointers

Author: `anomie`

I've been messing with pointers lately which never goes wrong, right?

## Dev Notes
Host the remote with `make run`, it is running by default on port 6969.

Source code (`pointer.c`) and binary are provided to the competitors. Copy the binary down from the docker with
```
docker cp pointers:/pwn/pointers .
```

## Solution
Looking at the source, there's a 2-byte overflow because `010` is 8 in octal notation, but `read()` takes in 10 bytes. Some dynamic analysis will reveal that we can use this to overwrite the lower 2 bytes of `rbp`. Examining the disassembly after the call to `vuln()`, we see that the function pointer is loaded from `rbp - 0x20`:

``` 
0x4012b1 <main+74>        mov    rax, QWORD PTR [rbp-0x20]
0x4012b5 <main+78>        mov    QWORD PTR [rbp-0x8], rax
0x4012b9 <main+82>        mov    rdx, QWORD PTR [rbp-0x8]
0x4012bd <main+86>        mov    eax, 0x0
0x4012c2 <main+91>        call   rdx
```

Our goal is to call `win()`, which is stored at 8 bytes beyond the leaked address. Thus, we need to have `rbp - 0x20 == leak + 8`, so we want to overwrite `rbp` with `leak + 40`. Luckily for us, the upper 6 bytes are already the same, so we just need to send 8 bytes of padding, followed by the target address. See `solve.py` for the full solution.

Flag: `gigem{small_overflows_are_still_effective}`
