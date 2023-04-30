# nothing 2

Author: `anomie`

Another funny obfuscation technique.

## Dev notes
Only given file is the binary `nothing-2`.

## Solution
We can start by opening the binary in Ghidra (spoilers, the decompilation is mostly unhelpful). Since the binary is stripped, we can look at the entry point and check the first argument to `__libc_start_main()` to look at `main()`:
```c
void FUN_0010132b(void)
{
  puts("this is main");
  return;
}
```
Obviously, there's more to this binary than whatever's in the decompilation, so we can switch to looking at the assembly. After scrolling a bit in the output of `objdump`, I found this interesting snippet:
```x86asm
118f:	83 7d 9c 02          	cmp    DWORD PTR [rbp-0x64],0x2
1193:	0f 85 86 01 00 00    	jne    131f <__cxa_finalize@plt+0x2bf>
1199:	c6 45 b0 6f          	mov    BYTE PTR [rbp-0x50],0x6f
119d:	c6 45 b1 61          	mov    BYTE PTR [rbp-0x4f],0x61
11a1:	c6 45 b2 6f          	mov    BYTE PTR [rbp-0x4e],0x6f
...
```
The immediates are ASCII characters, so I decided to force Ghidra to decompile this section (right-click the first instruction and select "Create Function"), and lo and behold, a _very_ sus function magically appeared:
```c
void sus(void)

{
  size_t sVar1;
  char *pcVar2;
  long unaff_RBP;
  
  if (*(int *)(unaff_RBP + -100) == 2) {
    *(undefined *)(unaff_RBP + -0x50) = 'o';
    *(undefined *)(unaff_RBP + -0x4f) = 'a';
    *(undefined *)(unaff_RBP + -0x4e) = 'o';
    *(undefined *)(unaff_RBP + -0x4d) = '9';
    *(undefined *)(unaff_RBP + -0x4c) = '{';
    *(undefined *)(unaff_RBP + -0x4b) = '5';
    *(undefined *)(unaff_RBP + -0x4a) = 'i';
    *(undefined *)(unaff_RBP + -0x49) = 'n';
    *(undefined *)(unaff_RBP + -0x48) = '1';
    *(undefined *)(unaff_RBP + -0x47) = '7';
    *(undefined *)(unaff_RBP + -0x46) = 's';
    *(undefined *)(unaff_RBP + -0x45) = 'm';
    *(undefined *)(unaff_RBP + -0x44) = 't';
    *(undefined *)(unaff_RBP + -0x43) = 'i';
    *(undefined *)(unaff_RBP + -0x42) = 's';
    *(undefined *)(unaff_RBP + -0x41) = 'n';
    *(undefined *)(unaff_RBP + -0x40) = 'm';
    *(undefined *)(unaff_RBP + -0x3f) = '6';
    *(undefined *)(unaff_RBP + -0x3e) = 'b';
    *(undefined *)(unaff_RBP + -0x3d) = 'm';
    *(undefined *)(unaff_RBP + -0x3c) = 't';
    *(undefined *)(unaff_RBP + -0x3b) = '1';
    *(undefined *)(unaff_RBP + -0x3a) = 'b';
    *(undefined *)(unaff_RBP + -0x39) = 'p';
    *(undefined *)(unaff_RBP + -0x38) = 'r';
    *(undefined *)(unaff_RBP + -0x37) = 'z';
    *(undefined *)(unaff_RBP + -0x36) = 'n';
    *(undefined *)(unaff_RBP + -0x35) = 'm';
    *(undefined *)(unaff_RBP + -0x34) = 'r';
    *(undefined *)(unaff_RBP + -0x33) = 'b';
    *(undefined *)(unaff_RBP + -0x32) = '{';
    *(undefined *)(unaff_RBP + -0x31) = 'y';
    *(undefined *)(unaff_RBP + -0x30) = 'e';
    *(undefined *)(unaff_RBP + -0x2f) = '1';
    *(undefined *)(unaff_RBP + -0x2e) = '2';
    sVar1 = strlen((char *)(unaff_RBP + -0x50));
    *(size_t *)(unaff_RBP + -0x18) = sVar1;
    sVar1 = strlen(*(char **)(*(long *)(unaff_RBP + -0x70) + 8));
    *(size_t *)(unaff_RBP + -0x20) = sVar1;
    if (*(long *)(unaff_RBP + -0x18) == *(long *)(unaff_RBP + -0x20)) {
      *(undefined8 *)(unaff_RBP + -8) = 0;
      while (*(ulong *)(unaff_RBP + -8) < *(ulong *)(unaff_RBP + -0x20)) {
        pcVar2 = strchr("abcdefghijklmnopqrstuvwxyz1234567890{}_",
                        (int)*(char *)(*(long *)(unaff_RBP + -8) +
                                      *(long *)(*(long *)(unaff_RBP + -0x70) + 8)));
        *(char **)(unaff_RBP + -0x28) = pcVar2 + -0x102020;
        if (0x26 < *(ulong *)(unaff_RBP + -0x28)) {
          return;
        }
        if ("4piq9zovafg8{1hkcm7std03xle}ry6w_ujn52b"[*(long *)(unaff_RBP + -0x28)] !=
            *(char *)(*(long *)(unaff_RBP + -8) + unaff_RBP + -0x50)) {
          return;
        }
        *(long *)(unaff_RBP + -8) = *(long *)(unaff_RBP + -8) + 1;
      }
      *(undefined *)(unaff_RBP + -0x5d) = 'c';
      *(undefined *)(unaff_RBP + -0x5c) = 'o';
      *(undefined *)(unaff_RBP + -0x5b) = 'r';
      *(undefined *)(unaff_RBP + -0x5a) = 'r';
      *(undefined *)(unaff_RBP + -0x59) = 'e';
      *(undefined *)(unaff_RBP + -0x58) = 'c';
      *(undefined *)(unaff_RBP + -0x57) = 't';
      *(undefined *)(unaff_RBP + -0x56) = ' ';
      *(undefined *)(unaff_RBP + -0x55) = 'f';
      *(undefined *)(unaff_RBP + -0x54) = 'l';
      *(undefined *)(unaff_RBP + -0x53) = 'a';
      *(undefined *)(unaff_RBP + -0x52) = 'g';
      *(undefined *)(unaff_RBP + -0x51) = '!';
      *(undefined *)(unaff_RBP + -0x50) = 0;
      puts((char *)(unaff_RBP + -0x5d));
    }
  }
  return;
}
```
After finding this, it was relatively straightforward to reverse. One annoying thing was that all of the variables were expressed as offsets relative to `unaff_RBP`, so I couldn't just rename them in Ghidra. As a result, I just copied the decompilation outside of Ghidra and started manually trimming it down.

The code essentially does something like this:
```c
char* fixed = "oao9{5in17smtisnm6bmt1bprznmrb{ye12";
size_t fixed_len = strlen(fixed);
char* input = *(long *)(unaff_RBP + -0x70) + 8;
size_t input_len = strlen(input);
if (fixed_len == input_len) {
    for (size_t i = 0; i < input_len; ++i) {
        char* alphabet = "abcdefghijklmnopqrstuvwxyz1234567890{}_";
        size_t offset = strchr(alphabet, input[i]) - alphabet;
        if (invalid offset) {
            return;
        }
        if ("4piq9zovafg8{1hkcm7std03xle}ry6w_ujn52b"[offset] != fixed[i]) {
            return;
        }
    }
    puts("correct flag!");
}

```
To actually get the flag, I wrote a short Python script to brute force the input because I was tired:
```python
fixed = "oao9{5in17smtisnm6bmt1bprznmrb{ye12"
fixed2 = "4piq9zovafg8{1hkcm7std03xle}ry6w_ujn52b"
alphabet = "abcdefghijklmnopqrstuvwxyz1234567890{}_"
flag = ""
for f in fixed:
    for j, a in enumerate(alphabet):
        if f == fixed2[j]:
            flag += a
            break
print(flag)
```

Flag: `gigem{c0nstruct0r5_run_b3f0r3_m41n}`

