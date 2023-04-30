# Unlucky

Author: `nhwn`

Luck won't save you here. Have fun trying to get the flag!
## Solution
A simple glance makes it seem like the seed is 69, but that's not quite the case. It's the address of the `static int`. Since we are given the address of `main` during execution, we just need to look at the binary and figure out the offset of seed. 

`objdump` can give us that. Looking at these few lines we can see the address of `main` and `seed` and calculate the offset:
```
    11e9: 48 8d 05 78 2e 00 00         	lea	rax, [rip + 11896]      # 0x4068 <seed.2870>
    11f0: 89 c7                        	mov	edi, eax
    11f2: e8 69 fe ff ff               	call	0x1060 <srand@plt>
    11f7: 48 8d 35 a7 ff ff ff         	lea	rsi, [rip - 89]         # 0x11a5 <main>
```

Then, we can write a program in c that will use `srand()` with the same seed and then output the first 7 random numbers.

The solution script uses the c program `rand_nums.c` to get the same 7 random numbers and pass them to the challenge binary. 

The flag is: `gigem{1_n33d_b3tt3r_3ntr0py_s0urc3s}`
