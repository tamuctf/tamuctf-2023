# Contrived Shellcode

Author: `anomie`

There's a 0% chance this has any real world application, but sometimes it's just fun to test your skills.

## Dev Notes
Host the remote with `make run`, it is running by default on port 7000.

Given files are the binary `contrived-shellcode` and the source code `contrived-shellcode.c`. Acquire them with `make dist`

## Solution
Using [capstone](https://www.capstone-engine.org/lang_python.html), we can check which x86-64 instructions fit the provided constraints. A simple Python script that finds valid instructions via brute force can be found in `insns.py`. Note that 0x0a (newline) is _not_ in the whitelist.

After digging through the list of valid instructions, some of the most interesting ones are:
```
add al, <valid immediate>
add byte ptr [rdx + rax], cl
```

After examining the disassembly of the program and running it in `gdb`, some interesting register values at the beginning of our shellcode's execution are:
```
rdx = <starting address of shellcode buffer>
rax = 0
rcx = 0x10
```

Combined with the previous x86-64 instructions, we can create a write primitive with 2 constraints:
1. The target address must be within 256 bytes of the start of the shellcode buffer.
2. The target byte must not be equal to 0x0a (mod 0x10).

Using this write primitive, we can create and execute instructions outside the initial whitelist at runtime. Here's what the first stage looks like:
1. Increment `rax` until it points a decent amount down the buffer. The second stage will start here.
2. Repeatedly spam `add byte ptr [rdx + rax], cl` to construct the most-significant nibble. The least-significant nibble should be set in advance during the initial read.
3. Advance `rax` to the next write target.
4. Repeat from #2 until the second stage is in memory.

The initial value of `rax` should be chosen such that the second stage is immediately after the first stage. Now, it's just a matter of crafting a second stage that fits the constraints of our write primitive. 

To ensure our second stage requires minimal effort from the first stage, we can have it read in a third stage with the `read()` syscall. 

```x86asm
b8 00 00 00 00       mov    eax, 0x0           ; rax = 0 (syscall number)
bf 00 00 00 00       mov    edi, 0x0           ; rdi = 0 (file descriptor is STDIN)
52                   push   rdx 
5e                   pop    rsi                ; rsi = <starting address of shellcode buffer>
81 e2 00 00 0f 00    and    edx, 0xf0000       ; rdx = <small-enough value to ensure the syscall succeeds>
0f 05                syscall
```

While this payload for the second stage is sub-par in terms of size, there are only 6 bytes with nibbles that we need to increment; the rest can be set in advance, which helps cut down on the number of bytes required for the first stage.

For the final payload that gets fed in via `read()`, we can send in off-the-shelf shellcode that drops a shell. However, before sending the final payload, we need to send padding equal to the sum of the lengths of the first two stages. This ensures that execution of the final payload will happen immediately after the second stage returns from the syscall.

The final size for the initial input is 220 bytes. See `solve.py` for details.

Flag: `gigem{Sh3llc0d1ng_1s_FuN}`
